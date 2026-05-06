"""Identity-related posture rules."""

from __future__ import annotations

from pathlib import Path

from agentveil_posture.report import Finding


HEADER_LIMIT_BYTES = 4096
PRIVATE_KEY_HEADERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
ENCRYPTED_KEY_MARKERS = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"Proc-Type: 4,ENCRYPTED",
)


def scan_identity_private_key_unencrypted(root: Path, path: Path) -> Finding | None:
    """Detect unencrypted private-key headers without exposing key material.

    Legacy PEM encryption markers are expected in the bounded header window,
    matching standard PEM output.
    """
    try:
        with path.open("rb") as handle:
            header = handle.read(HEADER_LIMIT_BYTES)
    except OSError:
        return None

    if any(marker in header for marker in ENCRYPTED_KEY_MARKERS):
        return None
    if not any(header.startswith(marker) for marker in PRIVATE_KEY_HEADERS):
        return None

    return Finding(
        rule_id="identity.private_key_unencrypted",
        severity="high",
        file=path.relative_to(root).as_posix(),
        line=1,
        message="Unencrypted private key file appears present.",
        remediation=(
            "Remove the key from the repository, rotate it if exposed, store it "
            "in a secret manager, and use encrypted private key material when "
            "local keys are unavoidable."
        ),
    )
