#!/usr/bin/env python3
"""Merge CodeQL SARIF and Codex Security-style findings into a demo report."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Location:
    path: str
    line: int
    role: str = "evidence"


@dataclass
class Finding:
    source: str
    finding_id: str
    title: str
    severity: str
    confidence: str
    category: str
    cwe: list[str]
    locations: list[Location]
    summary: str
    evidence: str
    remediation: str = ""
    attack_path: str = ""
    status: str = "candidate"
    related: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        cwe_key = ",".join(sorted(self.cwe)) or "none"
        paths = ",".join(sorted({loc.path for loc in self.locations}))
        return f"{cwe_key}|{self.category.lower()}|{paths}"

    def overlaps(self, other: "Finding") -> bool:
        own_cwe = set(self.cwe)
        other_cwe = set(other.cwe)
        if own_cwe and other_cwe and not (own_cwe & other_cwe):
            return False
        if self.category.lower() != other.category.lower():
            return False
        own_paths = {loc.path for loc in self.locations if loc.role in {"source", "root_control", "sink"}}
        other_paths = {loc.path for loc in other.locations if loc.role in {"source", "root_control", "sink"}}
        return bool(own_paths & other_paths)


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "note": 0}


def normalize_category(category: str) -> str:
    lowered = category.lower()
    if "sql-injection" in lowered or lowered == "sql injection":
        return "SQL injection"
    if "xss" in lowered or "cross-site" in lowered:
        return "Cross-site scripting"
    if "url-redirection" in lowered or "redirect" in lowered:
        return "Open redirect"
    if "request-forgery" in lowered or lowered == "server-side request forgery":
        return "Server-side request forgery"
    if "path-injection" in lowered:
        return "Path traversal"
    return category


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def severity_from_sarif(result: dict[str, Any], rule_index: dict[str, dict[str, Any]]) -> str:
    level = result.get("level", "warning")
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    rule = rule_index.get(result.get("ruleId", ""), {})
    tags = rule.get("properties", {}).get("tags", [])
    if "security-severity/9.0" in tags:
        return "critical"
    return "low"


def load_codeql_triage(path: Path | None) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    if path is None:
        return {}, []
    payload = load_json(path)
    findings = payload.get("findings", [])
    return {item["input_id"]: item for item in findings}, findings


def load_codeql_sarif(path: Path, triage_by_id: dict[str, dict[str, Any]] | None = None) -> list[Finding]:
    sarif = load_json(path)
    triage_by_id = triage_by_id or {}
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_index = {rule.get("id", ""): rule for rule in rules}
        for idx, result in enumerate(run.get("results", []), start=1):
            rule = rule_index.get(result.get("ruleId", ""), {})
            finding_id = result.get("partialFingerprints", {}).get("primaryLocationLineHash", f"codeql-{idx}")
            triage = triage_by_id.get(finding_id, {})
            verdict = triage.get("verdict")
            if verdict == "confirmed":
                status = "correlated"
                triage_evidence = triage.get("evidence", [])
                triage_path = triage.get("reachable_path", [])
            elif verdict == "not_actionable":
                status = "FP"
                triage_evidence = triage.get("counterevidence", [])
                triage_path = []
            else:
                status = "candidate"
                triage_evidence = []
                triage_path = []
            locations = []
            for loc in result.get("locations", []):
                physical = loc.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                locations.append(
                    Location(
                        path=artifact.get("uri", "unknown"),
                        line=int(region.get("startLine", 1)),
                        role="sink",
                    )
                )
            findings.append(
                Finding(
                    source="codeql",
                    finding_id=finding_id,
                    title=result.get("message", {}).get("text", rule.get("name", result.get("ruleId", "CodeQL finding"))),
                    severity=severity_from_sarif(result, rule_index),
                    confidence=triage.get("confidence", "medium"),
                    category=normalize_category(
                        rule.get("properties", {}).get("security-category", result.get("ruleId", "static-analysis"))
                    ),
                    cwe=rule.get("properties", {}).get("cwe", []),
                    locations=locations,
                    summary=result.get("message", {}).get("text", ""),
                    evidence=" ".join(triage_evidence) or rule.get("shortDescription", {}).get("text", ""),
                    remediation=triage.get("recommended_next_step", rule.get("help", {}).get("text", "")),
                    attack_path=" ".join(triage_path),
                    status=status,
                )
            )
    return findings


def load_codex_findings(path: Path) -> list[Finding]:
    payload = load_json(path)
    findings: list[Finding] = []
    for item in payload.get("findings", []):
        findings.append(
            Finding(
                source="codex-security",
                finding_id=item["id"],
                title=item["title"],
                severity=item["severity"],
                confidence=item["confidence"],
                category=item["category"],
                cwe=item.get("cwe", []),
                locations=[Location(**loc) for loc in item.get("locations", [])],
                summary=item["summary"],
                evidence=item["evidence"],
                remediation=item.get("remediation", ""),
                attack_path=item.get("attack_path", ""),
                status=item.get("status", "reportable"),
                related=item.get("related", []),
            )
        )
    return findings


def correlate(findings: list[Finding]) -> list[dict[str, Any]]:
    clustered: list[list[Finding]] = []
    for finding in findings:
        for group in clustered:
            if any(finding.overlaps(existing) for existing in group):
                group.append(finding)
                break
        else:
            clustered.append([finding])

    correlated = []
    for grouped in clustered:
        grouped.sort(key=lambda f: (f.source, f.finding_id))
        severity = max(grouped, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity
        statuses = {f.status for f in grouped}
        if "correlated" in statuses:
            status = "correlated"
        elif "reportable" in statuses:
            status = "reportable"
        elif statuses == {"FP"}:
            status = "FP"
        else:
            status = "candidate"
        sources = sorted({f.source for f in grouped})
        primary = next((f for f in grouped if f.source == "codex-security"), grouped[0])
        correlated.append(
            {
                "correlation_key": primary.fingerprint(),
                "title": primary.title,
                "severity": severity,
                "confidence": primary.confidence,
                "status": status,
                "sources": sources,
                "count": len(grouped),
                "finding_ids": [f.finding_id for f in grouped],
                "category": primary.category,
                "cwe": primary.cwe,
                "locations": [loc.__dict__ for f in grouped for loc in f.locations],
                "summary": primary.summary,
                "evidence": primary.evidence,
                "attack_path": primary.attack_path,
                "remediation": primary.remediation,
            }
        )
    correlated.sort(key=lambda row: (SEVERITY_RANK.get(row["severity"], 0), row["title"]), reverse=True)
    return correlated


def render_markdown(
    target: dict[str, Any], rows: list[dict[str, Any]], codeql_triage: list[dict[str, Any]]
) -> str:
    reportable = [row for row in rows if row["status"] in {"reportable", "correlated"}]
    correlated_alerts = [item for item in codeql_triage if item.get("verdict") == "confirmed"]
    false_positive_alerts = [item for item in codeql_triage if item.get("verdict") == "not_actionable"]
    lines = [
        f"# Hybrid Security Triage: {target['name']}",
        "",
        f"- Target: `{target['repository']}`",
        f"- Version: `{target['version']}`",
        f"- Commit: `{target['commit']}`",
        f"- Validation mode: `{target['validation_mode']}`",
        f"- Reportable consolidated rows: `{len(reportable)}`",
        f"- CodeQL alerts reviewed: `{len(codeql_triage)}`",
        f"- CodeQL alerts correlated: `{len(correlated_alerts)}`",
        f"- CodeQL false positives: `{len(false_positive_alerts)}`",
    ]
    complementary = target.get("complementary_scan")
    if complementary:
        lines.extend(
            [
                "",
                "## Lightweight Complementary Codex Security Scan",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Engine | {complementary['engine']} |",
                f"| Coverage | **{complementary['coverage']}** |",
                f"| Files reviewed | {complementary['reviewed_files']} |",
                f"| New reportable findings | {complementary['reportable_findings']} |",
                f"| Deferred candidates | {complementary.get('deferred_candidates', 0)} |",
                f"| Explicit exclusion | {complementary['excluded_paths']} |",
                f"| Cost control | {complementary['exclusion_reason']} |",
                f"| Scope manifest | `{complementary['scope_manifest']}` |",
                f"| Mocked-canary evidence | `{complementary['validation_artifact']}` |",
                "",
                "Reviewed files: " + ", ".join(f"`{path}`" for path in complementary["included_paths"]) + ".",
            ]
        )
    lines.extend(
        [
            "",
            "## Consolidated Findings",
            "",
            "| # | Finding | Severity | Confidence | Sources | Status |",
            "| ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for index, row in enumerate(rows, start=1):
        lines.append(
            f"| {index} | {row['title']} | {row['severity']} | {row['confidence']} | {', '.join(row['sources'])} | {row['status']} |"
        )

    if codeql_triage:
        lines.extend(
            [
                "",
                "## CodeQL Alert Verdicts",
                "",
                "Every imported alert is preserved here for auditability. `correlated` means Codex validation found a supported source/control/sink path; `FP` means local evidence defeated the alert's security claim.",
                "",
                "| # | Alert | Rule / finding | Location | Verdict | Confidence | Rationale |",
                "| ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for index, item in enumerate(codeql_triage, start=1):
            normalized = item.get("normalized_input", {})
            location = normalized.get("vulnerable_component", "unknown")
            verdict = "correlated" if item.get("verdict") == "confirmed" else "FP"
            reasons = item.get("evidence", []) if verdict == "correlated" else item.get("counterevidence", [])
            rationale = " ".join(reasons).replace("|", "\\|")
            lines.append(
                f"| {index} | `{item['input_id']}` | {item['title']} | `{location}` | **{verdict}** | {item['confidence']} | {rationale} |"
            )

    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                "",
                f"## {index}. {row['title']}",
                "",
                f"- Severity: `{row['severity']}`",
                f"- Confidence: `{row['confidence']}`",
                f"- Category: `{row['category']}`",
                f"- CWE: `{', '.join(row['cwe']) or 'none'}`",
                f"- Sources: `{', '.join(row['sources'])}`",
                f"- Finding IDs: `{', '.join(row['finding_ids'])}`",
                "",
                "### Evidence",
                "",
                row["evidence"],
                "",
                "### Validated Attack Path",
                "",
                row["attack_path"] or "No validated attack path recorded.",
                "",
                "### Affected Locations",
                "",
            ]
        )
        for loc in row["locations"]:
            lines.append(f"- `{loc['path']}:{loc['line']}` ({loc['role']})")
        lines.extend(["", "### Remediation", "", row["remediation"] or "No remediation recorded."])

    lines.extend(
        [
            "",
            "## Demo Notes",
            "",
            "This report used static source/control/sink review plus local mocked canaries. Network, database, and target file-write sinks were replaced with recorders; no public target, cloud metadata endpoint, credential store, or real sensitive service was contacted.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql", required=True, type=Path)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--codeql-triage", type=Path, help="Optional triage-finding/v0 verdicts for imported CodeQL alerts.")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()

    target = load_json(args.target)
    triage_by_id, codeql_triage = load_codeql_triage(args.codeql_triage)
    findings = load_codeql_sarif(args.codeql, triage_by_id) + load_codex_findings(args.codex)
    rows = correlate(findings)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(target, rows, codeql_triage), encoding="utf-8")
    args.json_out.write_text(
        json.dumps({"target": target, "findings": rows, "codeql_triage": codeql_triage}, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
