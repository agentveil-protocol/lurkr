from __future__ import annotations

from lurkr.scanner import scan_path


RULE_ID = "agent.python_fastapi_path_auth_no_host_validation"


def _findings(tmp_path):
    return [finding for finding in scan_path(tmp_path).findings if finding.rule_id == RULE_ID]


def test_class_middleware_reading_url_path_without_trusted_host_fires(tmp_path):
    (tmp_path / "auth_middleware.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "app = FastAPI()\n\n"
        "class AuthMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        path = request.url.path\n"
        "        if path.startswith('/admin'):\n"
        "            return await self._reject()\n"
        "        return await call_next(request)\n\n"
        "    async def _reject(self):\n"
        "        return None\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.line == 8
    assert finding.file == "auth_middleware.py"
    assert "GHSA-86qp-5c8j-p5mr" in finding.message
    assert "TrustedHostMiddleware" in finding.remediation


def test_decorated_function_middleware_reading_url_path_fires(tmp_path):
    (tmp_path / "auth_decorator.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.middleware('http')\n"
        "async def enforce_admin_paths(request, call_next):\n"
        "    if request.url.path.startswith('/admin'):\n"
        "        return None\n"
        "    return await call_next(request)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 7


def test_non_http_middleware_decorator_does_not_fire(tmp_path):
    (tmp_path / "websocket_decorator.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.middleware('websocket')\n"
        "async def log_ws_paths(request, call_next):\n"
        "    return request.url.path\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_aliased_base_http_middleware_import_still_fires(tmp_path):
    (tmp_path / "aliased_middleware.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware as BHM\n\n"
        "app = FastAPI()\n\n"
        "class AuthMiddleware(BHM):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        if request.url.path.startswith('/admin'):\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 8


def test_class_middleware_with_trusted_host_in_same_file_does_not_fire(tmp_path):
    (tmp_path / "auth_with_trusted_host.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "from starlette.middleware.trustedhost import TrustedHostMiddleware\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(TrustedHostMiddleware, allowed_hosts=['example.com'])\n\n"
        "class AuthMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        if request.url.path.startswith('/admin'):\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_local_trusted_host_name_without_import_does_not_suppress(tmp_path):
    (tmp_path / "local_trusted_host_name.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "app = FastAPI()\n"
        "TrustedHostMiddleware = object()\n\n"
        "class AuthMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        if request.url.path.startswith('/admin'):\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 9


def test_class_middleware_without_url_path_read_does_not_fire(tmp_path):
    (tmp_path / "method_only_middleware.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "app = FastAPI()\n\n"
        "class MethodGate(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        if request.method == 'TRACE':\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_raw_scope_path_read_does_not_fire(tmp_path):
    (tmp_path / "scope_path_middleware.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "app = FastAPI()\n\n"
        "class AuthMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        path = request.scope['path']\n"
        "        if path.startswith('/admin'):\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_file_without_fastapi_or_starlette_imports_does_not_fire(tmp_path):
    (tmp_path / "no_framework.py").write_text(
        "class FakeMiddleware:\n"
        "    def dispatch(self, request, call_next):\n"
        "        return request.url.path\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_url_path_read_in_helper_outside_middleware_body_does_not_fire(tmp_path):
    (tmp_path / "helper_outside_middleware.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "app = FastAPI()\n\n"
        "def is_admin_path(request):\n"
        "    return request.url.path.startswith('/admin')\n\n"
        "class NoopMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_qualified_base_class_via_module_import_fires(tmp_path):
    (tmp_path / "qualified_base.py").write_text(
        "from fastapi import FastAPI\n"
        "import starlette.middleware.base\n\n"
        "app = FastAPI()\n\n"
        "class AuthMiddleware(starlette.middleware.base.BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        if request.url.path.startswith('/admin'):\n"
        "            return None\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 8
