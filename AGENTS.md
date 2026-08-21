# AGENTS.md — SupplyGuard

## Project
SupplyGuard is an open-source CLI + Flask dashboard tool that scans a codebase for software
supply chain risk by combining SBOM generation, OSS vulnerability correlation
(OSV.dev), secrets scanning (Gitleaks), and static analysis for AI-generated
code smells (Semgrep + custom rules), produces one weighted risk score, and
provides a self-healing remediation loop to safely fix findings.

## Tech stack (do not deviate without asking)
- Python 3.11+, Flask for the web dashboard, Click for the CLI
- SQLite via SQLAlchemy for scan persistence (no external DB)
- Jinja2 + Chart.js (CDN) for the frontend — no React/Vue, keep it simple
- External tools invoked as subprocesses: cyclonedx-py, gitleaks, semgrep
- OSV.dev REST API via `requests` (no SDK)
- Anthropic API for optional LLM-assisted remediation patches

## Coding standards
- Type hints on every function signature
- Docstrings (Google style) on every public function/class
- No bare `except:` — always catch specific exceptions
- All subprocess calls use `subprocess.run(..., shell=False)` with a list of
  args, never a string — this tool scans for that exact antipattern
  elsewhere in the wild, it must not contain it itself
- All external HTTP calls have explicit timeouts
- No hardcoded paths — use `pathlib.Path` and config values

## Security requirements (this project IS a security tool — hold it to a higher bar than a normal app)
- Never log or persist a full secret value found by the secrets scanner —
  store only a redacted preview (first 3 + last 3 chars) plus file:line
- No eval, exec, or pickle.loads on any input, ever, anywhere in this repo
- Before marking any task complete, run `semgrep --config=auto` and
  `gitleaks detect` on the code you just wrote, and report the result in
  the Walkthrough

## Remediation safety rules (supplyguard/remediation/)
- `classify()` is the single source of truth for what gets auto-touched.
  MANUAL_REQUIRED findings are NEVER passed to a fixer function — enforce
  this in the loop, not just by convention.
- Every fix attempt must go through verifier.py's backup → apply → check →
  keep-or-revert sequence. No fixer function is allowed to write directly
  to the target file without going through the verifier.
- LLM fixer prompts must include the vulnerable snippet, the CWE, and
  surrounding context, and must explicitly instruct the model to change
  only what's necessary and explain the fix in one sentence for the log.
  Never send the whole file — minimize blast radius and token use.
- `supplyguard fix` must never call `git push` or `git merge` to a remote
  under any circumstance. It stops at a clean local diff.
- Every RemediationAttempt row must store the actual diff text, not just
  a boolean "fixed: true/false" — the dashboard's whole value is showing
  what changed, not just claiming something changed.

## File structure rules
- One module = one responsibility (sbom/, vulns/, secrets/, sast/,
  scoring/, remediation/, web/)
- Nothing outside supplyguard/cli.py should call print() directly — use
  the logging module
- Tests live in tests/, mirroring the package structure, one test file per
  module minimum

## Output format
- Every module exposes a single typed entrypoint function returning a
  dataclass or Pydantic model, not a raw dict, so the scoring and
  remediation engines have a stable contract to consume
- Update README.md whenever you add a new CLI flag or route
