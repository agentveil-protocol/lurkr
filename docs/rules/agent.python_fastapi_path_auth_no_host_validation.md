# agent.python_fastapi_path_auth_no_host_validation

Detects FastAPI / Starlette middleware that makes path-based security decisions
by reading `request.url.path` when the same file shows no
`TrustedHostMiddleware` configuration. This is the deployment surface for
[GHSA-86qp-5c8j-p5mr / CVE-2026-48710](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr)
("Missing Host header validation poisons `request.url.path`, bypassing
path-based security checks", published 2026-05-21).

## What It Flags

The rule iterates every Python source file in the scan tree. For each file
that imports from `fastapi.*` or `starlette.*`, it looks for two middleware
shapes:

- Classes whose base class resolves to `starlette.middleware.base.BaseHTTPMiddleware`
  (or the FastAPI re-export), including aliased and module-qualified imports.
- Functions or async functions decorated with `@<app>.middleware("http")`,
  the canonical FastAPI / Starlette in-line HTTP middleware shape.

For each matching middleware definition, the rule reports the file when:

1. The middleware body reads any attribute chain ending in `.url.path` (for
   example `request.url.path`, `req.url.path`, or `event.request.url.path`).
2. The same file shows no resolved import or module-qualified reference of
   `TrustedHostMiddleware` from `starlette.middleware.trustedhost` or the
   FastAPI re-export.

The reported line is the first `.url.path` read inside the middleware body.

## Why It Matters

On affected Starlette versions (`<= 1.0.0`), the framework reconstructs
`request.url` by concatenating `http://{Host}{path}` and re-parsing the
result. A `Host` header that contains characters outside the
[RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2-6) /
[RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)
grammar — notably `/`, `?`, and `#` — moves the path / query / fragment
boundaries during re-parsing. The parsed `request.url.path` then no longer
matches the path the server actually received.

The router still dispatches on the raw `scope["path"]`, so the endpoint
executes. Any middleware that reads `request.url.path` for authorization,
allowlisting, or rate-limit keying sees the attacker-shaped path and can be
bypassed. Example from the advisory:

```http
GET /foo HTTP/1.1
Host: example.com/abc?bar=
```

is reconstructed as `http://example.com/abc?bar=/foo`, whose parsed `path`
is `/abc`. A middleware that only refuses requests for `/foo` will let this
one through.

`TrustedHostMiddleware`, when configured with a real `allowed_hosts` list and
placed before the path-based middleware, rejects malformed `Host` headers
before re-parse occurs and closes the bypass at the framework boundary.

## Triggers

Bad:

```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware


app = FastAPI()


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/admin"):
            return await self._reject()
        return await call_next(request)
```

The file has no `TrustedHostMiddleware`. A malformed `Host` header
(`Host: example.com/admin/../public?x=`) can make `request.url.path` resolve
to a path that does not start with `/admin`, even though the router still
dispatches to `/admin/...`. Lurkr reports the `request.url.path` read.

Good:

```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware


app = FastAPI()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com"])


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/admin"):
            return await self._reject()
        return await call_next(request)
```

`TrustedHostMiddleware` rejects malformed `Host` headers before the auth
middleware runs, so the path-based check is safe.

Also good:

```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware


app = FastAPI()


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.scope["path"]
        if path.startswith("/admin"):
            return await self._reject()
        return await call_next(request)
```

`request.scope["path"]` is the raw ASGI path that routing already uses and
is not affected by `Host` header reconstruction.

## Known Limitations

- The rule is single-file. `TrustedHostMiddleware` configured in a separate
  module that is imported into this file is not detected; treat the rule as a
  per-file smell, not a project-wide guarantee.
- The rule does not distinguish auth-decision reads of `request.url.path`
  from logging-only reads. A middleware that only logs the path is still
  flagged because the logged path will not match the dispatched path on a
  poisoned `Host` header.
- `request.url.path` reads in helper functions or modules outside the
  middleware body are not flagged. Move security-sensitive path reads inside
  the middleware definition so this rule and code review see them together.
- The rule does not parse `requirements.txt` or `pyproject.toml`. It does not
  attempt to determine the installed Starlette version. Treat any flagged
  file as risky until the project's `Host` validation story is verified end
  to end.
- Custom or vendored re-exports of `BaseHTTPMiddleware` or
  `TrustedHostMiddleware` outside `fastapi.*` / `starlette.*` are not
  recognised.

## Remediation

Add `TrustedHostMiddleware` with an explicit `allowed_hosts` allowlist
before any path-based middleware in the FastAPI / Starlette app, or read the
raw `scope["path"]` instead of `request.url.path` for security decisions.

Also upgrade Starlette to `1.0.1` or later. The patched version validates the
`Host` header against
[RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2-6) /
[RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)
when constructing `request.url` and falls back to `scope["server"]` for
malformed values.
