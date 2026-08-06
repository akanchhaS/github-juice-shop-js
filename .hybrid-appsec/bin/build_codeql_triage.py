#!/usr/bin/env python3
"""Build an auditable, one-result-per-alert triage artifact for Juice Shop."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


FALSE_POSITIVE_REASONS: dict[int, str] = {
    77: "The idMap key comes from the database-backed numeric user id, not an attacker-selected property name.",
    76: "The tokenMap key is a server-issued JWT at every shipped caller; no less-trusted actor controls an arbitrary property name.",
    75: "The URL-fragment key is written only to a new local object and the consumer reads only access_token; no privileged object or prototype sink is reached.",
    74: "Uploaded bytes are intentionally written only after image magic-byte validation, authentication, and construction of a fixed user-id/type path; the client filename cannot select the sink path.",
    72: "The reported regex is an end-to-end test assertion, not shipped runtime validation or a security control.",
    71: "The token-presence branch is followed by cryptographic jwt.verify before challenge state changes; presence alone does not authorize anything.",
    69: "A supplied token is verified with the public key before it is added to the authenticated-user map; the token-presence check is not the security decision.",
    66: "The throw is reachable only if a fixed local promotion template is missing or unreadable; request input cannot select or remove that file.",
    65: "The throw is reachable only if a fixed local profile template is missing or unreadable; request input cannot select or remove that file.",
    57: "The hidden privacy-proof route returns a fixed resource and has no endpoint-specific expensive or sensitive sink; generic request throttling is hardening, not proof of this alert.",
    56: "The hidden premium-reward route returns a fixed resource and has no endpoint-specific expensive or sensitive sink; generic request throttling is hardening, not proof of this alert.",
    55: "The hidden easter-egg route returns a fixed resource and has no endpoint-specific expensive or sensitive sink; generic request throttling is hardening, not proof of this alert.",
    50: "The delivery-status operation is protected by the accounting-role middleware; CodeQL did not establish a lower-privileged abuse path that rate limiting would prevent.",
    49: "Duplicate instance of the accounting-only delivery-status route; no lower-privileged abuse path specific to missing rate limiting is established.",
    48: "The all-orders read is accounting-role protected and CodeQL did not establish a lower-privileged resource-abuse path.",
    47: "Duplicate instance of the accounting-only all-orders read; no lower-privileged resource-abuse path is established.",
    46: "The current user's order-history read has no endpoint-specific expensive or cross-user sink tied to the absence of a rate limiter.",
    45: "The language-list route returns a bounded configuration list; no sensitive or meaningfully expensive sink is reached.",
    44: "The data-export handler is preceded by the same-path image CAPTCHA verification middleware, which is the repository's explicit anti-automation control for this operation.",
    42: "The whoami route performs bounded token/user lookup work; no endpoint-specific sensitive or expensive action is enabled by repeated requests.",
    41: "Duplicate instance of the bounded whoami route; no endpoint-specific sensitive or expensive action is enabled by repeated requests.",
    39: "The 2FA status route is authenticated and read-only; setup, verify, and disable operations have explicit rate limiters elsewhere in the same block.",
    38: "The cited line installs accounting authorization middleware and is not itself a resource-consuming endpoint or sensitive state transition.",
    35: "The log-file route performs a bounded file response; missing rate limiting is not the broken access/path control and no distinct abuse sink is established.",
    34: "The key-file route performs a bounded file response; rate limiting would not repair its separate file-access boundary and no distinct rate-abuse sink is established.",
    33: "The quarantine-file route performs a bounded file response; no endpoint-specific rate-abuse sink is established.",
    32: "The FTP file route performs a bounded file response; missing rate limiting is not the broken path/allowlist control and no distinct rate-abuse sink is established.",
    31: "The one-step '..' replacement only rewrites serve-index link markup; CodeQL does not connect it to a filesystem, redirect, script, or authorization sink.",
    30: "containsEscaped is challenge-solution comparison logic, not an input sanitizer protecting a product security boundary.",
    24: "The origin substring expression only detects whether the intentionally vulnerable CSRF challenge was solved; it does not authorize or reject the profile update.",
    23: "The referer substring expression only detects whether the intentionally vulnerable CSRF challenge was solved; it does not authorize or reject the profile update.",
    10: "The profile-image destination is built from a server-trusted numeric user id and a small extension allowlist; the attacker-controlled URL cannot select a path component.",
}


CORRELATED_REASONS: dict[int, str] = {
    73: "A mocked upload canary reached both the temporary-file write and archive extraction write; attacker-controlled names can escape their intended directories.",
    70: "A benign package.json.bak%00.md canary passes the extension check, is truncated after the check, and reaches sendFile as package.json.bak.",
    68: "The public repeat-notification query is decoded and a missing challenge name is concatenated into logger.warn without newline neutralization.",
    67: "Authenticated imageUrl input reaches the ambiguous repeated-wildcard regex before any length or format bound, creating a request-driven regex cost sink.",
    64: "A mocked attacker.invalid URL containing an allowlisted URL as a query substring was accepted and reached the redirect decision.",
    63: "The shipped page executes a protocol-relative third-party CDN script without an integrity attribute or first-party pinning.",
    62: "The shipped page executes a second protocol-relative third-party CDN script without an integrity attribute or first-party pinning.",
    61: "The unauthenticated profile route performs template reads/compilation and database work without a route limiter, providing a repeatable application-work sink.",
    60: "Second CodeQL instance on the profile route; the same unauthenticated request reaches template/database work without a limiter.",
    59: "The public video route streams a local video and honors attacker-controlled ranges without a route limiter, creating a bandwidth/file-I/O sink.",
    58: "The public promotion route reads files and compiles a Pug template per request without a route limiter.",
    54: "The authenticated like-review route performs multiple database operations and an intentional timer delay without a route limiter.",
    53: "The authenticated review update can issue a multi-record database mutation repeatedly without a route limiter.",
    52: "The product-review creation endpoint performs a database write without a route limiter.",
    51: "The public review lookup reaches a JavaScript $where database expression and intentional sleep behavior without a route limiter.",
    43: "The public track-order route reaches an attacker-built $where expression without a route limiter, enabling repeated database evaluation.",
    40: "The public login endpoint performs password hashing and a database authentication query without a login-specific rate limiter.",
    37: "The profile image upload repeatedly accepts memory-buffered data and performs filesystem/database writes without a route limiter.",
    36: "The public file upload can invoke archive parsing or a bounded two-second XML VM operation repeatedly without a route limiter.",
    29: "A non-string q value can reach length/substring operations before the SQL sink and cause request-processing failure; the handler does not enforce a string type.",
    28: "A non-string to value reaches the substring allowlist and then res.redirect without a string-type check, preserving a parameter-tampering path.",
    27: "User passwords are deterministically hashed with unsalted MD5 before storage/authentication, exactly matching the weak-hash claim.",
    26: "The search query parameter is explicitly passed to bypassSecurityTrustHtml and then rendered as trusted HTML.",
    25: "Cookie-authenticated state-changing routes, including POST /profile, have no CSRF token middleware; the local origin/referer code is challenge detection only.",
    22: "Authenticated req.body.id is passed directly as a MarsDB selector with multi:true, so object/operator input can alter the update set.",
    21: "A mocked q canary appeared verbatim inside the raw product-search SQL string.",
    20: "A mocked email canary appeared verbatim inside the raw login SQL authentication string.",
    19: "Attacker-controlled review id reaches the final MarsDB update selector without scalar validation.",
    18: "The same attacker-controlled review id reaches the delayed findOne selector without scalar validation.",
    17: "The same attacker-controlled review id reaches the first MarsDB update selector without scalar validation.",
    16: "The same attacker-controlled review id reaches the initial findOne selector without scalar validation.",
    15: "The repeated new password is accepted in a GET query parameter, exposing it through URLs, logs, and browser history.",
    14: "The new password is accepted in a GET query parameter, exposing it through URLs, logs, and browser history.",
    13: "The current password is accepted in a GET query parameter, exposing it through URLs, logs, and browser history.",
    12: "A mocked ../../ archive member passed the starts-with-style containment check and reached a write path outside uploads/complaints.",
    11: "The slash-only guard permits Windows backslash traversal on an officially supported Windows deployment before sendFile path resolution.",
    9: "The log-file slash-only guard permits Windows backslash traversal before sendFile path resolution.",
    8: "The encryption-key slash-only guard permits Windows backslash traversal before sendFile path resolution.",
    7: "An archive member path reaches createWriteStream without a correct containment check; the mocked canary escaped the complaints directory.",
    6: "The upload's attacker-controlled originalname is joined into the temporary path; a mocked ../../canary.zip resolved outside the intended temp directory.",
    5: "The public file route has both a poison-null extension-order bypass and a Windows backslash traversal path before sendFile.",
    4: "A mocked order id canary appeared inside the MarsDB $where JavaScript expression, changing its predicate.",
    3: "The public product id reaches a MarsDB $where JavaScript expression when container-only coercion is not active.",
    2: "A mocked .invalid imageUrl canary was passed unchanged to request.get; no real network request was made.",
    1: "Math.random output is used as the JWT verification secret for denyAll, a security-sensitive secret-generation use that requires a CSPRNG or explicit rejection middleware.",
}


RISK_ORDER = {
    "js/code-injection": 0,
    "js/sql-injection": 1,
    "js/zipslip": 2,
    "js/request-forgery": 3,
    "js/path-injection": 4,
    "js/xss": 5,
    "js/missing-token-validation": 6,
    "js/insufficient-password-hash": 7,
    "js/user-controlled-bypass": 8,
    "js/http-to-file-access": 9,
    "js/polynomial-redos": 10,
    "js/missing-rate-limiting": 11,
    "js/functionality-from-untrusted-source": 12,
    "js/type-confusion-through-parameter-tampering": 13,
    "js/log-injection": 14,
    "js/insecure-randomness": 15,
}


CANARY_ALERTS = {2, 4, 5, 6, 7, 12, 20, 21, 64, 70, 73}


def load_results(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["runs"][0]["results"]


def location_of(result: dict[str, Any]) -> tuple[str, int]:
    physical = result["locations"][0]["physicalLocation"]
    return physical["artifactLocation"]["uri"], int(physical["region"]["startLine"])


def build_finding(
    index: int,
    result: dict[str, Any],
    confirmed_rank: int | None,
    revision: str,
) -> dict[str, Any]:
    props = result.get("properties", {})
    alert_number = int(props["githubAlertNumber"])
    path, line = location_of(result)
    confirmed = alert_number in CORRELATED_REASONS
    reason = (CORRELATED_REASONS if confirmed else FALSE_POSITIVE_REASONS)[alert_number]
    method = "mocked local canary plus static source/control/sink trace" if alert_number in CANARY_ALERTS else "static source/control/sink trace"
    rule_id = result.get("ruleId", "unknown")
    title = result.get("message", {}).get("text", rule_id)
    return {
        "triage_item_id": f"triage-{index:03d}",
        "input_id": f"ghas-alert-{alert_number}",
        "source_type": "sarif",
        "title": title,
        "normalized_input": {
            "vulnerable_component": f"{path}:{line}",
            "claimed_source": "attacker-controlled HTTP input or runtime request" if confirmed else "scanner-claimed untrusted input",
            "claimed_sink": rule_id,
            "claimed_control": "missing, bypassed, or incomplete control identified by CodeQL",
            "affected_version_or_path": f"{revision}:{path}",
            "scanner_state": props.get("state"),
            "preconditions": ["target runs the checked-out Juice Shop revision"],
            "impact": title,
            "references": [props.get("githubHtmlUrl", "")],
        },
        "verdict": "confirmed" if confirmed else "not_actionable",
        "confidence": "high" if alert_number in CANARY_ALERTS or not confirmed else "medium",
        "affected_locations": [
            {
                "label": "root_control",
                "path": path,
                "lines": str(line),
                "detail": reason,
            }
        ],
        "reachable_path": [reason] if confirmed else [],
        "boundary_assessment": {
            "product_surface": "intentionally vulnerable hosted web application",
            "source_trust": "untrusted" if confirmed else "unknown",
            "boundary_crossed": True if confirmed else False,
            "policy_basis": "SECURITY.md and package.json identify this supported revision as an intentionally vulnerable web application",
        },
        "exploitability_stack_rank": {
            "rank_queue": "confirmed" if confirmed else None,
            "rank": confirmed_rank,
            "rationale": "ranked by attacker reachability, sink impact, and validation strength" if confirmed else "not actionable",
            "drivers": ["attacker reachability", "source-to-sink control", "guard strength"] if confirmed else [],
        },
        "evidence": [f"Validation method: {method}.", reason] if confirmed else [f"Validation method: {method}."],
        "counterevidence": [] if confirmed else [reason],
        "proof_gaps": [],
        "recommended_next_step": "correlate with the Codex Security result" if confirmed else "mark CodeQL alert as false positive in the demo report",
        "fix_finding_handoff": (
            f"Review {rule_id} at {path}:{line}; preserve the validated attacker boundary and replace the broken control described here: {reason}"
            if confirmed
            else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--repository-path", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    results = load_results(args.sarif)
    alert_numbers = {int(result["properties"]["githubAlertNumber"]) for result in results}
    decided = set(FALSE_POSITIVE_REASONS) | set(CORRELATED_REASONS)
    if alert_numbers != decided:
        missing = sorted(alert_numbers - decided)
        stale = sorted(decided - alert_numbers)
        raise SystemExit(f"decision coverage mismatch; missing={missing}, stale={stale}")

    confirmed_results = [result for result in results if int(result["properties"]["githubAlertNumber"]) in CORRELATED_REASONS]
    ranked = sorted(
        confirmed_results,
        key=lambda result: (
            RISK_ORDER.get(result.get("ruleId", ""), 999),
            -int(result["properties"]["githubAlertNumber"]),
        ),
    )
    ranks = {int(result["properties"]["githubAlertNumber"]): rank for rank, result in enumerate(ranked, start=1)}

    findings = []
    for index, result in enumerate(results, start=1):
        alert_number = int(result["properties"]["githubAlertNumber"])
        findings.append(build_finding(index, result, ranks.get(alert_number), args.revision))

    output = {
        "schema_version": "triage-finding/v0",
        "repository": {"path": args.repository_path, "revision": args.revision},
        "findings": findings,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    correlated = sum(item["verdict"] == "confirmed" for item in findings)
    print(f"wrote {len(findings)} alert verdicts: {correlated} correlated, {len(findings) - correlated} FP")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
