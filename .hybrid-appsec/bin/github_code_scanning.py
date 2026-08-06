#!/usr/bin/env python3
"""Plan and apply GitHub code-scanning dismissals and SARIF uploads safely."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_API_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2026-03-10"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def plan_digest(plan: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def validate_repository(repository: str) -> None:
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts) or any(part in {".", ".."} for part in parts):
        raise ValueError("repository must be in owner/name form")


def build_plan(
    triage: dict[str, Any],
    sarif_path: Path,
    repository: str,
    commit_sha: str,
    ref: str,
) -> dict[str, Any]:
    validate_repository(repository)
    if not ref.startswith("refs/"):
        raise ValueError("ref must be a fully qualified Git ref")
    dismissals = []
    for item in triage.get("findings", []):
        if item.get("verdict") != "not_actionable":
            continue
        scanner_state = item.get("normalized_input", {}).get("scanner_state")
        if scanner_state not in {None, "open"}:
            continue
        input_id = item.get("input_id", "")
        if not input_id.startswith("ghas-alert-"):
            raise ValueError(f"unexpected CodeQL input id: {input_id}")
        affected = item.get("normalized_input", {}).get("affected_version_or_path", "")
        if affected and not affected.startswith(f"{commit_sha}:"):
            raise ValueError(f"triage revision mismatch for {input_id}")
        counterevidence = " ".join(item.get("counterevidence", [])).strip()
        dismissals.append(
            {
                "alert_number": int(input_id.rsplit("-", 1)[1]),
                "input_id": input_id,
                "confidence": item.get("confidence", "medium"),
                "dismissed_reason": "false positive",
                "dismissed_comment": (
                    "Hybrid CodeQL + Codex Security validation at "
                    f"{commit_sha[:12]} found this alert unsupported: {counterevidence}"
                )[:1000],
            }
        )
    dismissals.sort(key=lambda row: row["alert_number"])

    sarif = load_json(sarif_path)
    result_count = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    plan: dict[str, Any] = {
        "schema_version": "github-code-scanning-actions/v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository": repository,
        "commit_sha": commit_sha,
        "ref": ref,
        "dismissals": dismissals,
        "sarif_upload": {
            "path": str(sarif_path.resolve()),
            "sha256": sha256_file(sarif_path),
            "result_count": result_count,
            "tool_name": "Hybrid AppSec: CodeQL + Codex Security",
        },
        "safety": {
            "default_mode": "plan",
            "recommended_dismissal_mode": "request",
            "requires_exact_plan_digest": True,
        },
    }
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def tls_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def validate_api_url(api_url: str) -> str:
    parsed = urlparse(api_url)
    if parsed.scheme == "https" and parsed.netloc:
        return api_url.rstrip("/")
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return api_url.rstrip("/")
    raise ValueError("API URL must use HTTPS; HTTP is accepted only for a loopback test server")


def request_json(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any],
    api_version: str,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        method=method,
        data=canonical_bytes(body),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "hybrid-appsec-codex-demo",
            "X-GitHub-Api-Version": api_version,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60, context=tls_context()) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"GitHub API {method} {url} returned HTTP {exc.code}: {body_text}") from exc


def apply_plan(
    plan: dict[str, Any],
    expected_digest: str,
    token: str,
    api_url: str,
    api_version: str,
    dismissal_mode: str,
    upload_sarif: bool,
) -> dict[str, Any]:
    actual_digest = plan_digest(plan)
    if plan.get("plan_sha256") != actual_digest or expected_digest != actual_digest:
        raise ValueError("plan digest mismatch; review and approve the exact current plan")
    api_url = validate_api_url(api_url)
    repository = plan["repository"]
    validate_repository(repository)
    receipt: dict[str, Any] = {
        "schema_version": "github-code-scanning-receipt/v1",
        "repository": repository,
        "plan_sha256": actual_digest,
        "dismissal_mode": dismissal_mode,
        "dismissals": [],
        "sarif_upload": None,
    }

    for dismissal in plan.get("dismissals", []):
        payload: dict[str, Any] = {
            "state": "dismissed",
            "dismissed_reason": "false positive",
            "dismissed_comment": dismissal["dismissed_comment"],
        }
        if dismissal_mode == "request":
            payload["create_request"] = True
        status, response = request_json(
            "PATCH",
            f"{api_url}/repos/{repository}/code-scanning/alerts/{dismissal['alert_number']}",
            token,
            payload,
            api_version,
        )
        receipt["dismissals"].append(
            {
                "alert_number": dismissal["alert_number"],
                "http_status": status,
                "state": response.get("state"),
                "request_created": dismissal_mode == "request",
            }
        )

    if upload_sarif:
        upload = plan["sarif_upload"]
        sarif_path = Path(upload["path"])
        if sha256_file(sarif_path) != upload["sha256"]:
            raise ValueError("SARIF changed after plan approval")
        encoded = base64.b64encode(gzip.compress(sarif_path.read_bytes(), mtime=0)).decode("ascii")
        status, response = request_json(
            "POST",
            f"{api_url}/repos/{repository}/code-scanning/sarifs",
            token,
            {
                "commit_sha": plan["commit_sha"],
                "ref": plan["ref"],
                "sarif": encoded,
                "tool_name": upload["tool_name"],
                "validate": True,
            },
            api_version,
        )
        receipt["sarif_upload"] = {
            "http_status": status,
            "sarif_id": response.get("id"),
            "url": response.get("url"),
            "result_count": upload["result_count"],
        }
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--triage", required=True, type=Path)
    plan_parser.add_argument("--sarif", required=True, type=Path)
    plan_parser.add_argument("--repository", required=True)
    plan_parser.add_argument("--commit-sha", required=True)
    plan_parser.add_argument("--ref", required=True)
    plan_parser.add_argument("--out", required=True, type=Path)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan", required=True, type=Path)
    apply_parser.add_argument("--confirm-plan-sha256", required=True)
    apply_parser.add_argument("--token-env", default="GITHUB_TOKEN")
    apply_parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL))
    apply_parser.add_argument(
        "--api-version", default=os.environ.get("GITHUB_API_VERSION", DEFAULT_API_VERSION)
    )
    apply_parser.add_argument("--dismissal-mode", choices=("request", "direct"), default="request")
    apply_parser.add_argument("--upload-sarif", action="store_true")
    apply_parser.add_argument("--receipt", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "plan":
        plan = build_plan(
            load_json(args.triage), args.sarif, args.repository, args.commit_sha, args.ref
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        print(
            f"planned {len(plan['dismissals'])} FP dismissals and "
            f"{plan['sarif_upload']['result_count']} SARIF results; "
            f"approval digest {plan['plan_sha256']}"
        )
        return 0

    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"{args.token_env} is required; do not place tokens in plan files or logs")
    plan = load_json(args.plan)
    receipt = apply_plan(
        plan,
        args.confirm_plan_sha256,
        token,
        args.api_url,
        args.api_version,
        args.dismissal_mode,
        args.upload_sarif,
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(
        f"applied {len(receipt['dismissals'])} dismissal actions; "
        f"SARIF upload={'submitted' if receipt['sarif_upload'] else 'skipped'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
