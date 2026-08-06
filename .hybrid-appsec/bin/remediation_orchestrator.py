#!/usr/bin/env python3
"""Generate, validate, and publish one consolidated defensive remediation PR."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def object_digest(value: dict[str, Any], digest_field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=check
    )


def require_clean_base(repo: Path, base_commit: str) -> None:
    status = run_git(repo, "status", "--porcelain").stdout.strip()
    if status:
        raise RuntimeError("target worktree must be clean before remediation begins")
    head = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    if head != base_commit:
        raise RuntimeError(f"target HEAD {head} does not match approved base commit {base_commit}")


def remediation_prompt(manifest: dict[str, Any]) -> str:
    item = manifest["work_items"][0]
    findings = json.dumps(item["findings"], indent=2)
    checks = "\n".join(f"- {command}" for command in item["validation_commands"])
    return f"""You are remediating an authorized synthetic repository for a defensive security demo.

Fix every validated finding below in one cohesive patch. Do not contact deployed targets, public systems, cloud metadata endpoints, or credential stores. Do not generate or run exploit payloads. Work only in this checkout.

Requirements:
- Inspect repository guidance and existing tests first.
- Fix root causes, not example payloads.
- Add regression tests for every changed security boundary.
- Preserve normal supported application behavior. Intentionally vulnerable challenge behavior is not a compatibility requirement for this protected fork.
- Avoid broad rewrites unrelated to the findings.
- Do not commit, push, or open a pull request.
- Run the available required checks and clearly report any check you could not run.

Required deterministic checks:
{checks}

Validated findings:
{findings}
"""


def run_agent(manifest: dict[str, Any], repo: Path, output: Path, codex_bin: str) -> None:
    require_clean_base(repo, manifest["target"]["base_commit"])
    prompt = remediation_prompt(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        codex_bin,
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--sandbox",
        "workspace-write",
        "--cd",
        str(repo),
        "--output-last-message",
        str(output),
        prompt,
    ]
    completed = subprocess.run(command, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Codex remediation exited with status {completed.returncode}")


def changed_paths(repo: Path, base_commit: str) -> list[str]:
    changed = run_git(repo, "diff", "--name-only", base_commit, "--").stdout.splitlines()
    untracked = run_git(repo, "ls-files", "--others", "--exclude-standard").stdout.splitlines()
    return sorted({line for line in [*changed, *untracked] if line})


def secret_pattern_hits(repo: Path, paths: list[str]) -> list[str]:
    patterns = [
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]
    hits = []
    for relative in paths:
        candidate = repo / relative
        if not candidate.is_file() or candidate.stat().st_size > 5 * 1024 * 1024:
            continue
        content = candidate.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(content) for pattern in patterns):
            hits.append(relative)
    return hits


def run_validation_command(repo: Path, command: str, timeout: int) -> dict[str, Any]:
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty validation command")
    started = datetime.now(timezone.utc)
    try:
        completed = subprocess.run(
            argv,
            cwd=repo,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "exit_code": completed.returncode,
            "passed": completed.returncode == 0,
            "duration_seconds": round(
                (datetime.now(timezone.utc) - started).total_seconds(), 3
            ),
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": None,
            "passed": False,
            "duration_seconds": timeout,
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": "validation command timed out",
        }


def run_agent_review(
    repo: Path,
    codex_bin: str,
    schema_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    prompt = (
        "Review this uncommitted security remediation. Fail if any validated root cause remains, "
        "if a security boundary regressed, if tests are missing for a material fix, or if the patch "
        "introduces a significant correctness regression. Return only the requested structured result."
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            codex_bin,
            "exec",
            "review",
            "--uncommitted",
            "--ephemeral",
            "--ignore-user-config",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            prompt,
        ],
        cwd=repo,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or not output_path.exists():
        return {
            "decision": "fail",
            "summary": f"Codex security review could not complete (exit {completed.returncode}).",
            "findings": [],
        }
    try:
        return load_json(output_path)
    except json.JSONDecodeError:
        return {
            "decision": "fail",
            "summary": "Codex security review did not return valid structured JSON.",
            "findings": [],
        }


def validate_patch(
    manifest: dict[str, Any],
    repo: Path,
    timeout: int,
    codex_bin: str,
    schema_path: Path,
    review_output: Path,
    skip_agent_review: bool,
) -> dict[str, Any]:
    item = manifest["work_items"][0]
    base_commit = manifest["target"]["base_commit"]
    paths = changed_paths(repo, base_commit)
    test_paths = [
        path
        for path in paths
        if any(part.lower() in {"test", "tests", "spec", "specs"} for part in Path(path).parts)
        or Path(path).name.lower().endswith((".test.js", ".spec.js", ".test.ts", ".spec.ts"))
    ]
    command_results = [
        run_validation_command(repo, command, timeout)
        for command in item.get("validation_commands", [])
    ]
    secret_hits = secret_pattern_hits(repo, paths)
    preliminary_blocker = (
        not paths
        or (item.get("require_regression_tests", True) and not test_paths)
        or any(not result["passed"] for result in command_results)
        or bool(secret_hits)
    )
    if preliminary_blocker:
        agent_review = {
            "decision": "fail",
            "summary": "Agent review was skipped because a deterministic publication gate failed.",
            "findings": [],
        }
    elif skip_agent_review:
        agent_review = {
            "decision": "fail" if item.get("agent_review_required", True) else "pass",
            "summary": "Agent review was skipped.",
            "findings": [],
        }
    else:
        agent_review = run_agent_review(repo, codex_bin, schema_path, review_output)

    blockers = []
    if not paths:
        blockers.append("patch contains no changed files")
    if item.get("require_regression_tests", True) and not test_paths:
        blockers.append("no regression test file changed")
    blockers.extend(
        f"required check failed: {result['command']}"
        for result in command_results
        if not result["passed"]
    )
    if secret_hits:
        blockers.append(
            "potential credential or private-key material detected in changed files: "
            + ", ".join(secret_hits)
        )
    if item.get("agent_review_required", True) and agent_review.get("decision") != "pass":
        blockers.append("Codex security diff review did not pass")

    receipt: dict[str, Any] = {
        "schema_version": "hybrid-remediation-validation/v1",
        "target": manifest["target"],
        "work_item_id": item["id"],
        "changed_paths": paths,
        "test_paths": test_paths,
        "commands": command_results,
        "secret_scan": {"passed": not secret_hits, "flagged_paths": secret_hits},
        "agent_review": agent_review,
        "blockers": blockers,
        "passed": not blockers,
    }
    receipt["receipt_sha256"] = object_digest(receipt, "receipt_sha256")
    return receipt


def github_request(
    method: str, url: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        method=method,
        data=canonical_bytes(body) if body is not None else None,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "hybrid-appsec-codex-demo",
            "X-GitHub-Api-Version": os.environ.get("GITHUB_API_VERSION", "2026-03-10"),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail}") from exc


def push_branch(repo: Path, repository: str, branch: str, token: str) -> None:
    askpass_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
                "  *Password*) printf '%s\\n' \"$GITHUB_APP_TOKEN\" ;;\n"
                "esac\n"
            )
            askpass_path = Path(handle.name)
        os.chmod(askpass_path, 0o700)
        env = os.environ.copy()
        env.update(
            {
                "GIT_ASKPASS": str(askpass_path),
                "GIT_TERMINAL_PROMPT": "0",
                "GITHUB_APP_TOKEN": token,
            }
        )
        subprocess.run(
            [
                "git",
                "push",
                f"https://github.com/{repository}.git",
                f"HEAD:refs/heads/{branch}",
            ],
            cwd=repo,
            env=env,
            text=True,
            check=True,
        )
    finally:
        if askpass_path is not None:
            askpass_path.unlink(missing_ok=True)


def publish_draft_pr(
    manifest: dict[str, Any],
    validation: dict[str, Any],
    expected_receipt_digest: str,
    repo: Path,
    token: str,
    api_url: str,
) -> dict[str, Any]:
    actual_digest = object_digest(validation, "receipt_sha256")
    if validation.get("receipt_sha256") != actual_digest or expected_receipt_digest != actual_digest:
        raise ValueError("validation receipt digest mismatch")
    if not validation.get("passed"):
        raise RuntimeError("validation did not pass; branch push and PR creation are blocked")
    item = manifest["work_items"][0]
    repository = manifest["target"]["repository"]
    branch = item["branch"]

    run_git(repo, "switch", "-C", branch)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-m", item["title"])
    push_branch(repo, repository, branch, token)

    validation_lines = [
        "",
        "## Validation evidence",
        "",
        *[
            f"- `{'PASS' if result['passed'] else 'FAIL'}` — `{result['command']}` ({result['duration_seconds']}s)"
            for result in validation["commands"]
        ],
        f"- `{'PASS' if validation['agent_review']['decision'] == 'pass' else 'FAIL'}` — Codex security diff review: {validation['agent_review']['summary']}",
        "",
        "## Changed files",
        "",
        *[f"- `{path}`" for path in validation["changed_paths"]],
        "",
        "This PR is intentionally opened as a draft. Human review and repository branch protections remain required before merge.",
    ]
    body = item["pr_body"] + "\n".join(validation_lines) + "\n"
    owner = repository.split("/", 1)[0]
    query = urllib.parse.urlencode({"state": "open", "head": f"{owner}:{branch}"})
    _, existing = github_request(
        "GET", f"{api_url.rstrip('/')}/repos/{repository}/pulls?{query}", token
    )
    if existing:
        raise RuntimeError(f"an open PR already exists for {branch}: {existing[0].get('html_url')}")
    status, response = github_request(
        "POST",
        f"{api_url.rstrip('/')}/repos/{repository}/pulls",
        token,
        {
            "title": item["title"],
            "head": branch,
            "base": manifest["target"]["base_ref"],
            "body": body,
            "draft": True,
            "maintainer_can_modify": True,
        },
    )
    return {
        "http_status": status,
        "number": response.get("number"),
        "html_url": response.get("html_url"),
        "branch": branch,
        "head_sha": run_git(repo, "rev-parse", "HEAD").stdout.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    agent_parser = subparsers.add_parser("run-agent")
    agent_parser.add_argument("--manifest", required=True, type=Path)
    agent_parser.add_argument("--repo", required=True, type=Path)
    agent_parser.add_argument("--agent-output", required=True, type=Path)
    agent_parser.add_argument("--codex-bin", default="codex")

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--manifest", required=True, type=Path)
    validate_parser.add_argument("--repo", required=True, type=Path)
    validate_parser.add_argument("--receipt", required=True, type=Path)
    validate_parser.add_argument("--review-output", required=True, type=Path)
    validate_parser.add_argument(
        "--review-schema",
        type=Path,
        default=Path(__file__).parents[1] / "schemas" / "remediation-review.schema.json",
    )
    validate_parser.add_argument("--timeout", type=int, default=1200)
    validate_parser.add_argument("--codex-bin", default="codex")
    validate_parser.add_argument("--skip-agent-review", action="store_true")

    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--manifest", required=True, type=Path)
    publish_parser.add_argument("--validation", required=True, type=Path)
    publish_parser.add_argument("--confirm-receipt-sha256", required=True)
    publish_parser.add_argument("--repo", required=True, type=Path)
    publish_parser.add_argument("--token-env", default="GITHUB_APP_TOKEN")
    publish_parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    publish_parser.add_argument("--receipt", required=True, type=Path)

    args = parser.parse_args()
    manifest = load_json(args.manifest)
    if args.command == "run-agent":
        run_agent(manifest, args.repo.resolve(), args.agent_output, args.codex_bin)
        return 0
    if args.command == "validate":
        receipt = validate_patch(
            manifest,
            args.repo.resolve(),
            args.timeout,
            args.codex_bin,
            args.review_schema,
            args.review_output,
            args.skip_agent_review,
        )
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(f"validation {'passed' if receipt['passed'] else 'failed'}; receipt {receipt['receipt_sha256']}")
        return 0 if receipt["passed"] else 1

    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"{args.token_env} is required")
    publication = publish_draft_pr(
        manifest,
        load_json(args.validation),
        args.confirm_receipt_sha256,
        args.repo.resolve(),
        token,
        args.api_url,
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(publication, indent=2) + "\n", encoding="utf-8")
    print(f"opened draft PR {publication['html_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
