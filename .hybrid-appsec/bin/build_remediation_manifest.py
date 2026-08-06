#!/usr/bin/env python3
"""Create one consolidated remediation work item for validated findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_manifest(
    triage: dict[str, Any],
    codex: dict[str, Any],
    hybrid_report: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    confirmed_codeql = [
        item for item in triage.get("findings", []) if item.get("verdict") == "confirmed"
    ]
    reportable_codex = [
        item for item in codex.get("findings", []) if item.get("status") == "reportable"
    ]
    consolidated = [
        item
        for item in hybrid_report.get("findings", [])
        if item.get("status") in {"correlated", "reportable"}
    ]
    affected_paths = sorted(
        {
            location.get("path", "unknown")
            for item in consolidated
            for location in item.get("locations", [])
            if location.get("path")
        }
    )
    finding_ids = sorted(
        {item["input_id"] for item in confirmed_codeql}
        | {item["id"] for item in reportable_codex}
    )
    allowed_ids = set(finding_ids)
    remediation_findings = []
    for item in consolidated:
        included_ids = [finding_id for finding_id in item.get("finding_ids", []) if finding_id in allowed_ids]
        if not included_ids:
            continue
        remediation_findings.append(
            {
                "title": item["title"],
                "finding_ids": included_ids,
                "severity": item.get("severity", "medium"),
                "confidence": item.get("confidence", "medium"),
                "category": item.get("category", "security"),
                "cwe": item.get("cwe", []),
                "locations": item.get("locations", []),
                "summary": item.get("summary", ""),
                "evidence": item.get("evidence", ""),
                "remediation": item.get("remediation", ""),
            }
        )
    remediation = target.get("remediation", {})
    branch = f"hybrid-fix/all-validated-{target['commit'][:8]}"

    body_lines = [
        "## Summary",
        "",
        "This draft PR remediates the validated findings produced by the hybrid CodeQL and Codex Security workflow. All validated findings are handled in one review unit.",
        "",
        "## Scope",
        "",
        f"- {len(confirmed_codeql)} confirmed CodeQL alerts",
        f"- {len(reportable_codex)} reportable Codex Security findings",
        f"- {len(consolidated)} consolidated vulnerability groups",
        f"- {len(affected_paths)} affected source paths",
        "- False positives and deferred candidates are excluded",
        "",
        "## Security objectives",
        "",
    ]
    for index, item in enumerate(consolidated, start=1):
        body_lines.append(
            f"{index}. **{item['title']}** — restore the relevant input-validation, authorization, query-construction, resource-control, or output-encoding boundary."
        )
    body_lines.extend(
        [
            "",
            "## Implementation expectations",
            "",
            "- Prefer narrow root-cause fixes over payload-specific blocking.",
            "- Add regression coverage for each changed security boundary.",
            "- Preserve supported application behavior; intentionally vulnerable challenge behavior is not a compatibility requirement for this protected fork.",
            "- Do not introduce network calls, credentials, or external-service dependencies into tests.",
            "",
            "## Validation required before publication",
            "",
        ]
    )
    commands = remediation.get("validation_commands", [])
    for command in commands:
        body_lines.append(f"- `{command}`")
    body_lines.extend(
        [
            "- Codex security diff review of the final patch",
            "- Clean-worktree and secret-pattern checks",
            "",
            "The automation replaces this section with exact command results, changed files, and residual-risk notes before it opens the draft PR. A failing required check blocks branch push and PR creation.",
        ]
    )

    return {
        "schema_version": "hybrid-remediation-manifest/v1",
        "strategy": "single_consolidated_pr",
        "target": {
            "repository": target["repository"],
            "base_ref": remediation.get("base_ref", "master"),
            "base_commit": target["commit"],
        },
        "policy": {
            "draft_pr_only": True,
            "merge_requires_human": True,
            "publish_requires_all_checks": True,
            "false_positives_excluded": True,
            "deferred_candidates_excluded": True,
        },
        "work_items": [
            {
                "id": "fix-all-validated-findings",
                "branch": branch,
                "title": "Remediate validated hybrid AppSec findings",
                "finding_ids": finding_ids,
                "findings": remediation_findings,
                "consolidated_finding_count": len(consolidated),
                "affected_paths": affected_paths,
                "validation_commands": commands,
                "require_regression_tests": remediation.get("require_regression_tests", True),
                "agent_review_required": remediation.get("agent_review_required", True),
                "pr_body": "\n".join(body_lines) + "\n",
            }
        ],
        "coverage": {
            "confirmed_codeql_alerts": len(confirmed_codeql),
            "reportable_codex_findings": len(reportable_codex),
            "consolidated_groups": len(consolidated),
            "work_items": 1,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql-triage", required=True, type=Path)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--hybrid-report", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    manifest = build_manifest(
        load_json(args.codeql_triage),
        load_json(args.codex),
        load_json(args.hybrid_report),
        load_json(args.target),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    coverage = manifest["coverage"]
    print(
        "wrote one remediation work item for "
        f"{coverage['confirmed_codeql_alerts']} CodeQL alerts and "
        f"{coverage['reportable_codex_findings']} Codex findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
