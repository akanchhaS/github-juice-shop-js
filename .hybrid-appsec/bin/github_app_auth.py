#!/usr/bin/env python3
"""Minimal GitHub App installation authentication without third-party packages."""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def private_key_from_env() -> str:
    key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
    if key:
        return key.replace("\\n", "\n")
    if key_path:
        return Path(key_path).read_text(encoding="utf-8")
    raise RuntimeError("GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH is required")


def sign_rs256(signing_input: bytes, private_key: str) -> bytes:
    key_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(private_key)
            handle.flush()
            os.chmod(handle.name, 0o600)
            key_path = Path(handle.name)
        completed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=signing_input,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("openssl could not sign the GitHub App JWT")
        return completed.stdout
    finally:
        if key_path is not None:
            key_path.unlink(missing_ok=True)


def build_app_jwt(app_id: str, private_key: str, now: int | None = None) -> str:
    issued = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)}
    signing_input = (
        f"{b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    ).encode("ascii")
    return f"{signing_input.decode('ascii')}.{b64url(sign_rs256(signing_input, private_key))}"


def mint_installation_token(
    app_id: str,
    installation_id: str,
    private_key: str,
    api_url: str = "https://api.github.com",
    api_version: str = "2026-03-10",
) -> dict[str, Any]:
    jwt = build_app_jwt(app_id, private_key)
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens",
        method="POST",
        data=b"{}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "User-Agent": "hybrid-appsec-codex-demo",
            "X-GitHub-Api-Version": api_version,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(
            f"GitHub installation token request returned HTTP {exc.code}: {body}"
        ) from exc
    if not result.get("token"):
        raise RuntimeError("GitHub installation token response did not contain a token")
    return result


def mint_from_environment() -> dict[str, Any]:
    app_id = os.environ.get("GITHUB_APP_ID")
    installation_id = os.environ.get("GITHUB_APP_INSTALLATION_ID")
    if not app_id or not installation_id:
        raise RuntimeError("GITHUB_APP_ID and GITHUB_APP_INSTALLATION_ID are required")
    return mint_installation_token(
        app_id,
        installation_id,
        private_key_from_env(),
        os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        os.environ.get("GITHUB_API_VERSION", "2026-03-10"),
    )
