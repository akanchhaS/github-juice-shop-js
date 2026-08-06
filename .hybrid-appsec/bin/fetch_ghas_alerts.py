#!/usr/bin/env python3
"""Fetch GitHub code-scanning alerts and convert them to demo SARIF."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def tls_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass

    for candidate in ("/etc/ssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem"):
        if Path(candidate).exists():
            return ssl.create_default_context(cafile=candidate)
    return ssl.create_default_context()


def load_env_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in {"GH_TOKEN", "GITHUB_TOKEN"} and key not in os.environ:
            os.environ[key] = value


def token_from_env() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN or GITHUB_TOKEN is required; do not paste tokens into chat.")
    return token


def fetch_json(url: str, token: str) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": os.environ.get("GITHUB_API_VERSION", "2026-03-10"),
            "User-Agent": "hybrid-appsec-codex-demo",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=tls_context()) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"GitHub API returned HTTP {exc.code}: {body}") from exc


def fetch_alerts(
    repository: str,
    token: str,
    state: str | None = "open",
    tool_name: str | None = None,
) -> list[dict[str, Any]]:
    states = (state,) if state else ("open", "dismissed", "fixed")
    alerts_by_number: dict[int, dict[str, Any]] = {}
    for requested_state in states:
        page = 1
        while True:
            query: dict[str, str | int] = {
                "per_page": 100,
                "page": page,
                "state": requested_state,
            }
            if tool_name:
                query["tool_name"] = tool_name
            batch = fetch_json(
                f"https://api.github.com/repos/{repository}/code-scanning/alerts"
                f"?{urllib.parse.urlencode(query)}",
                token,
            )
            if not batch:
                break
            for alert in batch:
                alerts_by_number[int(alert["number"])] = alert
            page += 1
    return [alerts_by_number[number] for number in sorted(alerts_by_number)]


def fetch_alert_instances(repository: str, alert_number: int, token: str) -> list[dict[str, Any]]:
    instances: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = fetch_json(
            f"https://api.github.com/repos/{repository}/code-scanning/alerts/"
            f"{alert_number}/instances?per_page=100&page={page}",
            token,
        )
        if not batch:
            return instances
        instances.extend(batch)
        page += 1


def severity_from_alert(alert: dict[str, Any]) -> str:
    security_severity = alert.get("rule", {}).get("security_severity_level")
    if security_severity:
        return security_severity.lower()
    return alert.get("rule", {}).get("severity", "warning").lower()


def cwe_from_tags(tags: list[str]) -> list[str]:
    cwes = []
    for tag in tags:
        match = re.search(r"cwe[-_/](\d+)", tag.lower())
        if match:
            cwes.append(f"CWE-{int(match.group(1))}")
    return sorted(set(cwes))


def category_from_rule(rule: dict[str, Any]) -> str:
    raw = (rule.get("id") or rule.get("name") or "").lower()
    if "sql-injection" in raw:
        return "SQL injection"
    if "xss" in raw or "cross-site" in raw:
        return "Cross-site scripting"
    if "url-redirection" in raw or "redirect" in raw:
        return "Open redirect"
    if "http-to-file-access" in raw:
        return "Network data written to file"
    if "request-forgery" in raw:
        return "Server-side request forgery"
    if "path-injection" in raw:
        return "Path traversal"
    if "code-injection" in raw:
        return "Code injection"
    if "password-hash" in raw:
        return "Weak password hashing"
    if "rate-limiting" in raw:
        return "Missing rate limiting"
    return rule.get("name", rule.get("id", "code scanning"))


def rule_to_sarif_rule(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule", {})
    tags = rule.get("tags", [])
    return {
        "id": rule.get("id", "github-code-scanning-alert"),
        "name": rule.get("name", rule.get("id", "GitHub code scanning alert")),
        "shortDescription": {"text": rule.get("description", "")},
        "help": {"text": rule.get("full_description", rule.get("description", ""))},
        "properties": {
            "security-category": category_from_rule(rule),
            "cwe": cwe_from_tags(tags),
            "tags": tags,
        },
    }


def select_instance(
    alert: dict[str, Any], instances: list[dict[str, Any]], target_commit: str | None
) -> dict[str, Any]:
    if target_commit:
        for instance in instances:
            if instance.get("commit_sha") == target_commit:
                return instance
    return alert.get("most_recent_instance", {}) or (instances[0] if instances else {})


def alert_to_result(
    alert: dict[str, Any], instances: list[dict[str, Any]], target_commit: str | None
) -> dict[str, Any]:
    rule = alert.get("rule", {})
    selected_instance = select_instance(alert, instances, target_commit)
    location = selected_instance.get("location", {})
    path = location.get("path", "unknown")
    start_line = location.get("start_line") or location.get("startLine") or 1
    return {
        "ruleId": rule.get("id", "github-code-scanning-alert"),
        "level": "error" if severity_from_alert(alert) in {"critical", "high"} else "warning",
        "message": {"text": alert.get("message", {}).get("text", rule.get("description", ""))},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": int(start_line)},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": f"ghas-alert-{alert.get('number', 'unknown')}"
        },
        "properties": {
            "githubAlertNumber": alert.get("number"),
            "githubHtmlUrl": alert.get("html_url"),
            "state": alert.get("state"),
            "instanceCount": len(instances),
            "commitSha": selected_instance.get("commit_sha"),
            "ref": selected_instance.get("ref"),
        },
    }


def to_sarif(
    alerts: list[dict[str, Any]],
    instances_by_alert: dict[int, list[dict[str, Any]]],
    target_commit: str | None,
) -> dict[str, Any]:
    rules_by_id = {}
    for alert in alerts:
        rule = rule_to_sarif_rule(alert)
        rules_by_id[rule["id"]] = rule
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "GitHub code scanning", "rules": list(rules_by_id.values())}},
                "results": [
                    alert_to_result(
                        alert,
                        instances_by_alert.get(int(alert.get("number", 0)), []),
                        target_commit,
                    )
                    for alert in alerts
                ],
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, help="Repository in owner/name form.")
    parser.add_argument("--out", required=True, type=Path, help="SARIF output path.")
    parser.add_argument("--env-file", type=Path, help="Optional dotenv file containing GH_TOKEN or GITHUB_TOKEN.")
    parser.add_argument(
        "--target-commit",
        help="Prefer an alert instance for this commit when GitHub provides one.",
    )
    parser.add_argument(
        "--state",
        choices=("open", "dismissed", "fixed", "all"),
        default="open",
        help="Alert state to fetch. 'all' retrieves open, dismissed, and fixed alerts.",
    )
    parser.add_argument(
        "--tool-name",
        help="Optional code-scanning tool filter, for example CodeQL.",
    )
    args = parser.parse_args()

    if args.env_file:
        load_env_file(args.env_file)

    token = token_from_env()
    alerts = fetch_alerts(
        args.repository,
        token,
        None if args.state == "all" else args.state,
        args.tool_name,
    )
    instances_by_alert = {
        int(alert["number"]): fetch_alert_instances(args.repository, int(alert["number"]), token)
        for alert in alerts
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(to_sarif(alerts, instances_by_alert, args.target_commit), indent=2) + "\n",
        encoding="utf-8",
    )
    instance_count = sum(len(instances) for instances in instances_by_alert.values())
    print(
        f"wrote {len(alerts)} code-scanning alerts ({instance_count} instances) to {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
