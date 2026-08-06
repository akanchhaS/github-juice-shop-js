# Hybrid AppSec workflow

This package brings the `Assume/hybrid-appsec-codex-demo` workflow into the
repository it evaluates. It is intentionally isolated under `.hybrid-appsec/`
so the demo application remains unchanged.

The workflow performs these steps:

1. Fetch CodeQL alerts for the pinned Juice Shop revision.
2. Apply the checked-in, revision-bound validation ledger.
3. Combine retained CodeQL alerts with the lightweight Codex Security finding
   adapter.
4. Produce filtered SARIF and a content-addressed GitHub action plan.
5. In `request` mode, use a repository-scoped GitHub App token to request FP
   dismissals and upload the filtered SARIF.
6. Optionally generate one consolidated remediation patch, validate it, and
   publish a draft PR. Merge is always manual.

The initial branch push runs only `plan` mode. It performs no alert dismissal,
SARIF upload, remediation, branch publication, or pull-request creation.

## Required configuration after review

For scheduled `request` mode, configure these Actions secrets:

- `HYBRID_GITHUB_APP_ID`
- `HYBRID_GITHUB_APP_PRIVATE_KEY`

The App installation must be limited to this repository and have code-scanning
alerts read/write permission. Optional remediation additionally needs:

- `OPENAI_API_KEY` secret
- `HYBRID_REMEDIATION_ENABLED=true` repository variable
- `HYBRID_PUBLISH_DRAFTS=true` repository variable only when draft publication
  is approved
- `CODEX_CLI_VERSION=<reviewed version>` repository variable
- A protected `hybrid-appsec-remediation` Actions environment

The checked-in Codex Security finding file is the bounded result adapter for the
pinned commit. It is not a fresh Codex Security scan on each run; replacing it
with current native worker output is a production-integration step.
