#!/usr/bin/env python3
"""Run the daily GitHub App triage pipeline with plan-first mutations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from build_hybrid_sarif import build_sarif
from fetch_ghas_alerts import (
    alert_to_result,
    fetch_alert_instances,
    fetch_alerts,
    rule_to_sarif_rule,
)
from github_app_auth import mint_from_environment
from github_code_scanning import apply_plan, build_plan


REPO_ROOT = Path(__file__).parents[1]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def token() -> str:
    if os.environ.get("GITHUB_APP_ID") and os.environ.get("GITHUB_APP_INSTALLATION_ID"):
        installation = mint_from_environment()
        return installation["token"]
    existing = os.environ.get("GITHUB_TOKEN")
    if existing:
        return existing
    raise RuntimeError("GitHub App credentials or GITHUB_TOKEN are required")


def fetch_live_sarif(repository: str, commit_sha: str, auth_token: str) -> dict[str, Any]:
    alerts = fetch_alerts(repository, auth_token, state=None, tool_name="CodeQL")
    instances = {
        int(alert["number"]): fetch_alert_instances(repository, int(alert["number"]), auth_token)
        for alert in alerts
    }
    rules = {rule_to_sarif_rule(alert)["id"]: rule_to_sarif_rule(alert) for alert in alerts}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "GitHub code scanning", "rules": list(rules.values())}},
                "results": [
                    alert_to_result(alert, instances[int(alert["number"])], commit_sha)
                    for alert in alerts
                ],
            }
        ],
    }


def run_checked(*args: str) -> None:
    subprocess.run([sys.executable, *args], cwd=REPO_ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, default=REPO_ROOT / "fixtures/target-profile.juice-shop.json")
    parser.add_argument(
        "--codex-findings",
        type=Path,
        default=REPO_ROOT / "fixtures/codex-security-juice-shop.sample.json",
        help="Current Codex Security adapter output for the same commit.",
    )
    parser.add_argument("--target-checkout", type=Path, default=Path("/workspace/target"))
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("plan", "request"), default="plan")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    args = parser.parse_args()

    target = load_json(args.target)
    auth_token = token()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_sarif_path = out_dir / "codeql-alerts.sarif"
    triage_path = out_dir / "codeql-triage.json"
    report_md_path = out_dir / "hybrid-triage-report.md"
    report_json_path = out_dir / "hybrid-triage-report.json"
    upload_sarif_path = out_dir / "hybrid-upload.sarif"
    actions_plan_path = out_dir / "github-actions-plan.json"
    remediation_path = out_dir / "remediation-manifest.json"

    write_json(
        raw_sarif_path,
        fetch_live_sarif(target["repository"], target["commit"], auth_token),
    )
    run_checked(
        "bin/build_codeql_triage.py",
        "--sarif",
        str(raw_sarif_path),
        "--revision",
        target["commit"],
        "--repository-path",
        str(args.target_checkout),
        "--out",
        str(triage_path),
    )
    run_checked(
        "bin/hybrid_triage.py",
        "--codeql",
        str(raw_sarif_path),
        "--codeql-triage",
        str(triage_path),
        "--codex",
        str(args.codex_findings),
        "--target",
        str(args.target),
        "--out",
        str(report_md_path),
        "--json-out",
        str(report_json_path),
    )
    write_json(
        upload_sarif_path,
        build_sarif(
            load_json(raw_sarif_path),
            load_json(triage_path),
            load_json(report_json_path),
            target["repository"],
            target["commit"],
            "refs/heads/" + target.get("remediation", {}).get("base_ref", target["version"]),
        ),
    )
    plan = build_plan(
        load_json(triage_path),
        upload_sarif_path,
        target["repository"],
        target["commit"],
        "refs/heads/" + target.get("remediation", {}).get("base_ref", target["version"]),
    )
    write_json(actions_plan_path, plan)
    run_checked(
        "bin/build_remediation_manifest.py",
        "--codeql-triage",
        str(triage_path),
        "--codex",
        str(args.codex_findings),
        "--hybrid-report",
        str(report_json_path),
        "--target",
        str(args.target),
        "--out",
        str(remediation_path),
    )

    summary: dict[str, Any] = {
        "mode": args.mode,
        "repository": target["repository"],
        "commit_sha": target["commit"],
        "plan_sha256": plan["plan_sha256"],
        "false_positive_actions": len(plan["dismissals"]),
        "sarif_results": plan["sarif_upload"]["result_count"],
        "remediation_work_items": 1,
    }
    if args.mode == "request":
        receipt = apply_plan(
            plan,
            plan["plan_sha256"],
            auth_token,
            args.api_url,
            os.environ.get("GITHUB_API_VERSION", "2026-03-10"),
            "request",
            True,
        )
        write_json(out_dir / "github-actions-receipt.json", receipt)
        summary["github_actions_receipt"] = "github-actions-receipt.json"
    write_json(out_dir / "run-summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
