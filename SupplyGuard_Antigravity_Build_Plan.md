# SupplyGuard — Antigravity Build Plan

An AI-aware software supply chain security scanner. Combines SBOM generation, OSS
vulnerability correlation (OSV.dev), secrets scanning (Gitleaks), and static analysis
tuned for AI-generated code smells (Semgrep + a custom rule pack) into one weighted
risk score and dashboard.

Whole stack is free/open source: Antigravity (public preview), Semgrep Community
Edition, Gitleaks (MIT), OSV.dev API, CycloneDX.

---

## 1. Architecture

```
              ┌─────────────────────────────┐
  repo path → │   SupplyGuard CLI (Click)    │
              └──────────────┬──────────────┘
                              │ orchestrates
        ┌──────────┬─────────┼─────────┬──────────┐
        ▼          ▼         ▼         ▼          ▼
     [SBOM]     [OSV.dev]  [Gitleaks] [Semgrep]     │
   cyclonedx-py  vuln       secrets   SAST +         │
                 lookup     scan      custom AI-     │
                                      code rules      │
        └──────────┴─────────┴─────────┴─────────────┘
                              │
                              ▼
                   [Scoring Engine] → SQLite (findings + score)
                              │
                              ▼
                 [Flask + Chart.js Dashboard]
```

**Why wrap existing tools instead of building SAST/SCA from scratch:** it's faster,
more credible in an interview ("I know when to integrate vs. reinvent"), and more
accurate. Your original contribution is (a) the custom Semgrep rule pack targeting
AI-code smells and (b) the correlation/scoring layer that unifies all four sources —
which is the actual gap in the market this project is based on.

---

## 2. Repo layout

```
supplyguard/
├── AGENTS.md
├── .agent/
│   └── rules/
│       ├── security-policy.md
│       └── code-style.md
├── README.md
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── supplyguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── sbom/
│   │   ├── __init__.py
│   │   └── generator.py
│   ├── vulns/
│   │   ├── __init__.py
│   │   └── osv_client.py
│   ├── secrets/
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── sast/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   └── rules/
│   │       └── ai-code-smells.yml
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── engine.py
│   └── web/
│       ├── __init__.py
│       ├── app.py
│       ├── routes.py
│       ├── templates/
│       │   ├── base.html
│       │   ├── dashboard.html
│       │   └── scan_detail.html
│       └── static/
│           ├── css/
│           └── js/
├── tests/
│   ├── test_sbom.py
│   ├── test_osv_client.py
│   ├── test_secrets.py
│   ├── test_sast.py
│   └── test_scoring.py
├── examples/
│   └── vulnerable-demo-app/
├── docs/
│   └── architecture.md
└── .github/
    └── workflows/
        └── supplyguard-ci.yml
```

---

## 3. Antigravity project setup

1. Open Antigravity 2.0 → New Project → select/create the `supplyguard/` folder.
2. Settings → Autonomy profile → **Review-driven development** (balanced checkpoints;
   flip individual missions to more autonomous later if you trust the output).
3. Create `AGENTS.md` in the project root — paste the content below. Every agent
   spawned in this project reads it first.
4. Create `.agent/rules/security-policy.md` and `.agent/rules/code-style.md` — paste
   the content below.
5. Pick your model per mission: use the strongest available reasoning model for the
   planning-heavy missions (1, 3, 4 — they involve designing rules/schemas), a faster
   model is fine for 2 and 6.

### AGENTS.md

```markdown
# AGENTS.md — SupplyGuard

## Project
SupplyGuard is a CLI + Flask dashboard tool that scans a codebase for software
supply chain risk by combining SBOM generation, OSS vulnerability correlation
(OSV.dev), secrets scanning (Gitleaks), and static analysis for AI-generated
code smells (Semgrep + custom rules), then produces one weighted risk score.

## Tech stack (do not deviate without asking)
- Python 3.11+, Flask for the web dashboard, Click for the CLI
- SQLite via SQLAlchemy for scan persistence (no external DB)
- Jinja2 + Chart.js (CDN) for the frontend — no React/Vue, keep it simple
- External tools invoked as subprocesses: cyclonedx-py, gitleaks, semgrep
- OSV.dev REST API via `requests` (no SDK)

## Coding standards
- Type hints on every function signature
- Docstrings (Google style) on every public function/class
- No bare `except:` — always catch specific exceptions
- All subprocess calls use `subprocess.run(..., shell=False)` with a list of
  args, never a string — this tool scans for that exact antipattern
  elsewhere in the wild, it must not contain it itself
- All external HTTP calls have explicit timeouts
- No hardcoded paths — use `pathlib.Path` and config values

## Security requirements (this project IS a security tool — hold it to a
higher bar than a normal app)
- Never log or persist a full secret value found by the secrets scanner —
  store only a redacted preview (first 3 + last 3 chars) plus file:line
- No eval, exec, or pickle.loads on any input, ever, anywhere in this repo
- Before marking any task complete, run `semgrep --config=auto` and
  `gitleaks detect` on the code you just wrote, and report the result in
  the Walkthrough

## File structure rules
- One module = one responsibility (sbom/, vulns/, secrets/, sast/,
  scoring/, web/)
- Nothing outside supplyguard/cli.py should call print() directly — use
  the logging module
- Tests live in tests/, mirroring the package structure, one test file per
  module minimum

## Output format
- Every module exposes a single typed entrypoint function returning a
  dataclass or Pydantic model, not a raw dict, so the scoring engine has a
  stable contract to consume
- Update README.md whenever you add a new CLI flag or route
```

### .agent/rules/security-policy.md

```markdown
# Rule: security-policy

## When to apply
All Python files, especially supplyguard/secrets/ and supplyguard/web/

## Rules
- Never write a real secret, API key, or credential into any file in this
  repo, including test fixtures. Use obviously-fake values like
  "FAKE_KEY_FOR_TESTING_DO_NOT_USE" and note in a comment that it's fake.
- Any environment variable or credential the app needs at runtime is read
  via os.environ.get() with no default baked in, and documented (name
  only, no value) in .env.example
- The Flask app must not run with debug=True unless FLASK_ENV=development
  is explicitly set
```

### .agent/rules/code-style.md

```markdown
# Rule: code-style

## When to apply
All .py files

## Rules
- Follow PEP 8, enforced via black + ruff (add both to requirements-dev.txt)
- Max function length ~40 lines — split if longer
- Prefer pathlib over os.path
- f-strings only for string formatting, never % or .format()
```

---

## 4. Build sequence

Stage 1 (parallel — 3 agents): Missions 1, 2, 3
Stage 2 (solo, depends on Stage 1): Mission 4
Stage 3 (parallel — 2 agents, depends on Stage 2): Missions 5, 6
Stage 4 (solo, depends on everything): Mission 7

Review the Implementation Plan before approving each mission, and read the
Walkthrough when it finishes before starting the next dependent stage.

---

### Mission 1 — SBOM + OSV vulnerability correlation

```
Build the SBOM and vulnerability correlation module for SupplyGuard.

Create supplyguard/sbom/generator.py:
- A function generate_sbom(project_path: Path, output_path: Path) -> Path
  that shells out to cyclonedx-py's `requirements` subcommand to build a
  CycloneDX JSON SBOM from requirements.txt if one exists in project_path.
  Check `cyclonedx-py requirements --help` yourself to confirm the exact
  current flags (they vary by version) rather than guessing.
- Raise a clear, actionable error if cyclonedx-py isn't installed, and
  handle the case where there's no requirements.txt gracefully.

Create supplyguard/vulns/osv_client.py:
- A function batch_query(components: list[Component]) -> list[VulnMatch]
  that POSTs to https://api.osv.dev/v1/querybatch in chunks of 100, using
  {"package": {"name": ..., "ecosystem": "PyPI"}, "version": ...} per query
- For every hit, fetch the full record from GET
  https://api.osv.dev/v1/vulns/{id} for severity and summary
- 10-second timeout on every request, retry once on timeout
- Return a typed dataclass VulnMatch: package, version, vuln_id, severity,
  summary, fixed_version (if present in the affected ranges)

Write unit tests in tests/test_sbom.py and tests/test_osv_client.py that
mock the subprocess call and the HTTP calls — don't hit the real network
in tests. Show me the Implementation Plan before you start.
```

### Mission 2 — Secrets scanner

```
Build the secrets scanning module for SupplyGuard.

Create supplyguard/secrets/scanner.py:
- A function scan_secrets(project_path: Path) -> list[SecretFinding] that
  shells out to `gitleaks detect --source <project_path> --report-format
  json --report-path <temp file> --no-git`. Assume the gitleaks binary is
  on PATH; if it isn't, raise a clear error with an install link.
- Parse the JSON report into a typed SecretFinding dataclass: file, line,
  rule_id, match_preview — REDACTED, only the first 3 and last 3
  characters of the matched string, nothing else. This is a security
  tool; it must never leak the very secrets it finds.
- Never write the full matched secret to any log, file, or return value —
  check every code path for this before finishing.

Write tests in tests/test_secrets.py using a small fixture repo with a
fake, clearly-not-real secret (e.g. "FAKE_KEY_FOR_TESTING_DO_NOT_USE") to
confirm both detection and redaction work. Show me the plan first.
```

### Mission 3 — SAST engine + custom AI-code-smell rules

```
Build the static analysis module for SupplyGuard, focused on patterns
common in AI/LLM-generated code.

Create supplyguard/sast/rules/ai-code-smells.yml — a Semgrep rule pack,
one rule per CWE, researching the correct current Semgrep pattern syntax
for each:
1. SQL query built by string formatting/concatenation instead of
   parameterized queries (CWE-89)
2. Flask/FastAPI route handling delete/update/admin actions with no
   authentication decorator or dependency (CWE-862)
3. eval(), exec(), or pickle.loads() called on a non-literal variable
   (CWE-94 / CWE-502)
4. subprocess call with shell=True and a non-literal argument (CWE-78)
5. requests call with verify=False (CWE-295)
6. Flask app.run() with debug=True (CWE-489)
7. Password hashing with md5 or sha1 instead of bcrypt/argon2/scrypt
   (CWE-916)
8. JWT decode with verify_signature/verify set False, or algorithms=["none"]
   (CWE-347)
9. CORS Access-Control-Allow-Origin "*" combined with credentials support
   (CWE-942)
10. Python's random module (not secrets module) used to generate a token,
    password, or session ID (CWE-330)

Create supplyguard/sast/scanner.py:
- A function run_sast(project_path: Path) -> list[SastFinding] that shells
  out to `semgrep --config=supplyguard/sast/rules/ai-code-smells.yml
  --config=p/security-audit --json <project_path>` (our custom rules plus
  Semgrep's public security-audit pack) and parses the JSON into a typed
  SastFinding dataclass: file, line, rule_id, severity, cwe, message

Write tests in tests/test_sast.py: for each of the 10 rules, one small
inline vulnerable snippet that must trigger it and one equivalent SAFE
snippet that must NOT trigger it (checks for false positives). Show me
the Implementation Plan, including the exact Semgrep pattern for each
rule, before writing any code.
```

### Mission 4 — Scoring engine + persistence + CLI wiring

```
Wire SupplyGuard's core pipeline together.

Create supplyguard/models.py with SQLAlchemy models:
- Scan(id, project_path, started_at, finished_at, risk_score)
- Finding(id, scan_id FK, source [sbom/osv/secrets/sast], severity, file,
  line, message, raw_json)

Create supplyguard/scoring/engine.py:
- calculate_risk_score(vulns, secrets, sast_findings) -> int (0-100),
  using this transparent weighted formula (document the weights in the
  docstring so the score is auditable, not a black box):
  - +10 per OSV critical severity, +5 per high, +2 per medium/low
  - +15 per secret found (heaviest weight — immediately exploitable)
  - +8 per SAST high-severity finding, +3 per medium
  - cap total at 100

Create supplyguard/cli.py using Click:
- `supplyguard scan <path>`: sbom generation -> osv correlation -> secrets
  scan -> sast scan -> scoring, in that order. Run secrets scan and sast
  scan in parallel via concurrent.futures since neither depends on the
  other. Persist results via SQLAlchemy to a local supplyguard.db SQLite
  file. Print a summary table to the terminal.
- `supplyguard report <scan_id>`: prints a detailed breakdown of a past
  scan.

Show me the Implementation Plan before starting. Once done, run
`supplyguard scan .` against this project's own repo as a smoke test and
show me the Walkthrough with the real output.
```

### Mission 5 — Flask dashboard

```
Build the SupplyGuard web dashboard.

Create supplyguard/web/app.py (Flask app factory) and routes.py:
- GET / — list of past scans with risk score and date
- GET /scan/<id> — detail view for one scan

Build templates/dashboard.html and scan_detail.html with Jinja2, extending
a shared base.html. Use Chart.js (CDN) for:
- A gauge/donut chart of the overall risk score
- A pie chart of SBOM component composition
- A bar chart of findings by severity, grouped by source (SBOM/OSV,
  secrets, SAST)
Below the charts, a sortable, filterable findings table (filter by
severity and source) — plain JS, no framework.

Dark-mode by default, clean professional security-dashboard look — this
needs to look credible in a demo video, not like a Bootstrap default. Open
it in the browser yourself, verify each chart renders with real data from
a scan, and screenshot it in the Walkthrough.
```

### Mission 6 — Vulnerable demo app + CI integration

```
Build a small intentionally-vulnerable demo Flask app in
examples/vulnerable-demo-app/ that SupplyGuard can scan to demonstrate
every detection category:
- A route with a raw SQL string-concatenation query
- A hardcoded API key constant, clearly fake and labeled
  FAKE_KEY_FOR_TESTING_DO_NOT_USE
- An admin-deletion route with no auth check
- One outdated dependency in requirements.txt with a known OSV CVE —
  research and pick a real one, and confirm via the OSV API that it
  actually returns a hit before finalizing the version
- app.run(debug=True)

Then create .github/workflows/supplyguard-ci.yml: installs SupplyGuard,
runs `supplyguard scan .` against examples/vulnerable-demo-app on every
push, posts the risk score as a PR comment, fails the build if
risk_score > 40.

Confirm the workflow syntax is valid and the demo app genuinely trips
every rule category by running the scan locally first and showing me the
Walkthrough with the findings table.
```

### Mission 7 — README + docs

```
Write README.md:
- One-paragraph pitch citing the real problem: a 2026 Omdia/Docker survey
  of 400 security professionals found 39% struggle to quickly remediate
  vulnerabilities and 35% are specifically worried about AI-generated
  vulnerable code; separately, industry analysis of AI-assisted codebases
  has found roughly a tenfold rise in flagged security findings.
- Architecture diagram (mermaid) showing the four signal sources feeding
  the scoring engine
- Quickstart: install steps, `supplyguard scan .`, dashboard screenshot
- A "why these tools" section explaining the choice to integrate
  Semgrep/Gitleaks/OSV/CycloneDX rather than reimplement them, and where
  the original contribution is (the custom AI-code-smell rule pack + the
  correlation/scoring engine)
- MIT license, build-status badge

Also write docs/architecture.md with more implementation detail for
anyone extending it.
```

---

## 5. Resume bullet (once built)

> Built SupplyGuard, a software supply-chain security scanner unifying SBOM
> generation (CycloneDX), OSS vulnerability correlation (OSV.dev), secrets
> detection (Gitleaks), and a custom 10-rule Semgrep pack targeting
> AI-generated code vulnerabilities (CWE-mapped) into one weighted risk
> score with a Flask/Chart.js dashboard and GitHub Actions CI gate;
> architecture grounded in a 400-respondent 2026 industry survey on AI's
> impact on software supply chain risk.
