#!/usr/bin/env python3
"""Build upload-ready SARIF from validated CodeQL and new Codex findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "note": "note",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_rule_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]+", "-", value).strip("-")


def location(path: str, line: int) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": max(1, int(line))},
        }
    }


def stable_fingerprint(kind: str, identifiers: list[str], locations: list[dict[str, Any]]) -> str:
    material = json.dumps(
        {"kind": kind, "ids": sorted(identifiers), "locations": locations},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def codeql_rule(original: dict[str, Any]) -> dict[str, Any]:
    original_id = original.get("id", "unknown")
    properties = original.get("properties", {})
    return {
        "id": safe_rule_id(f"hybrid/validated-codeql/{original_id}"),
        "name": f"Validated {original.get('name', original_id)}",
        "shortDescription": original.get("shortDescription", {"text": original_id}),
        "fullDescription": {
            "text": "A CodeQL alert retained after repository-aware Codex validation."
        },
        "help": original.get("help", original.get("shortDescription", {"text": original_id})),
        "properties": {
            "tags": ["security", "hybrid-appsec", "validated-codeql"],
            "originalRuleId": original_id,
            "security-category": properties.get("security-category", original_id),
            "cwe": properties.get("cwe", []),
        },
    }


def codex_rule(finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = finding["finding_ids"][0]
    return {
        "id": safe_rule_id(f"hybrid/codex-security/{finding_id}"),
        "name": safe_rule_id(finding["title"]).replace("-", " "),
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": finding.get("summary", finding["title"])},
        "help": {"text": finding.get("remediation") or "Review and remediate the validated finding."},
        "properties": {
            "tags": ["security", "hybrid-appsec", "codex-security"],
            "security-category": finding.get("category", "security"),
            "cwe": finding.get("cwe", []),
        },
    }


def build_sarif(
    source_sarif: dict[str, Any],
    triage: dict[str, Any],
    hybrid_report: dict[str, Any],
    repository: str,
    commit_sha: str,
    ref: str,
) -> dict[str, Any]:
    triage_by_id = {item["input_id"]: item for item in triage.get("findings", [])}
    original_rules: dict[str, dict[str, Any]] = {}
    source_results: list[dict[str, Any]] = []
    for run in source_sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            original_rules[rule.get("id", "unknown")] = rule
        source_results.extend(run.get("results", []))

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for source in source_results:
        input_id = source.get("partialFingerprints", {}).get("primaryLocationLineHash", "")
        decision = triage_by_id.get(input_id)
        if not decision or decision.get("verdict") != "confirmed":
            continue
        original_rule_id = source.get("ruleId", "unknown")
        rule = codeql_rule(original_rules.get(original_rule_id, {"id": original_rule_id}))
        rules[rule["id"]] = rule
        evidence = " ".join(decision.get("evidence", [])).strip()
        title = decision.get("title", source.get("message", {}).get("text", original_rule_id))
        alert_number = source.get("properties", {}).get("githubAlertNumber")
        result_locations = source.get("locations", [])
        results.append(
            {
                "ruleId": rule["id"],
                "level": source.get("level", "warning"),
                "message": {
                    "text": f"Validated CodeQL alert #{alert_number}: {title}. {evidence}".strip()
                },
                "locations": result_locations,
                "partialFingerprints": {
                    "primaryLocationLineHash": stable_fingerprint(
                        "validated-codeql", [input_id], result_locations
                    )
                },
                "properties": {
                    "hybridStatus": "validated",
                    "source": "codeql",
                    "originalAlertId": input_id,
                    "originalAlertNumber": alert_number,
                    "originalRuleId": original_rule_id,
                    "originalAlertUrl": source.get("properties", {}).get("githubHtmlUrl"),
                    "confidence": decision.get("confidence", "medium"),
                    "repository": repository,
                    "commitSha": commit_sha,
                },
            }
        )

    for finding in hybrid_report.get("findings", []):
        if finding.get("status") != "reportable":
            continue
        rule = codex_rule(finding)
        rules[rule["id"]] = rule
        finding_locations = [
            location(item.get("path", "unknown"), item.get("line", 1))
            for item in finding.get("locations", [])
        ] or [location("unknown", 1)]
        finding_ids = finding.get("finding_ids", [])
        result: dict[str, Any] = {
            "ruleId": rule["id"],
            "level": LEVEL_BY_SEVERITY.get(finding.get("severity", "medium"), "warning"),
            "message": {
                "text": (
                    f"Codex Security finding: {finding['title']}. "
                    f"{finding.get('summary', '')} Evidence: {finding.get('evidence', '')}"
                ).strip()
            },
            "locations": [finding_locations[0]],
            "partialFingerprints": {
                "primaryLocationLineHash": stable_fingerprint(
                    "codex-security", finding_ids, finding_locations
                )
            },
            "properties": {
                "hybridStatus": "reportable",
                "source": "codex-security",
                "findingIds": finding_ids,
                "confidence": finding.get("confidence", "medium"),
                "severity": finding.get("severity", "medium"),
                "repository": repository,
                "commitSha": commit_sha,
                "remediation": finding.get("remediation", ""),
            },
        }
        if len(finding_locations) > 1:
            result["relatedLocations"] = [
                {"id": index, **item}
                for index, item in enumerate(finding_locations[1:], start=1)
            ]
        results.append(result)

    confirmed_count = sum(
        item.get("verdict") == "confirmed" for item in triage.get("findings", [])
    )
    reportable_count = sum(
        item.get("status") == "reportable" for item in hybrid_report.get("findings", [])
    )
    if len(results) != confirmed_count + reportable_count:
        raise ValueError(
            "output coverage mismatch: "
            f"results={len(results)} confirmed={confirmed_count} reportable={reportable_count}"
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": f"hybrid-appsec/{repository}/{ref}"},
                "tool": {
                    "driver": {
                        "name": "Hybrid AppSec: CodeQL + Codex Security",
                        "informationUri": "https://github.com/Assume/hybrid-appsec-codex-demo",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "versionControlProvenance": [
                    {
                        "repositoryUri": f"https://github.com/{repository}",
                        "revisionId": commit_sha,
                        "branch": ref,
                    }
                ],
                "properties": {
                    "validatedCodeqlResults": confirmed_count,
                    "newCodexSecurityResults": reportable_count,
                    "excludedFalsePositives": sum(
                        item.get("verdict") == "not_actionable"
                        for item in triage.get("findings", [])
                    ),
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql", required=True, type=Path)
    parser.add_argument("--codeql-triage", required=True, type=Path)
    parser.add_argument("--hybrid-report", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    payload = build_sarif(
        load_json(args.codeql),
        load_json(args.codeql_triage),
        load_json(args.hybrid_report),
        args.repository,
        args.commit_sha,
        args.ref,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    result_count = len(payload["runs"][0]["results"])
    print(f"wrote {result_count} uploadable results to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
