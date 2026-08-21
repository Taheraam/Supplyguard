# SupplyGuard v2 — Scan, Score, and Self-Heal

Supersedes/extends `SupplyGuard_Antigravity_Build_Plan.md`. Same foundation (SBOM,
OSV, Gitleaks, Semgrep, Flask+Chart.js dashboard) plus a remediation engine that
fixes what's safe to fix, verifies every fix, and loops until nothing auto-fixable
is left — while never silently touching anything that needs a human decision.

---

## 1. Why not "fix everything blindly"

A leaked secret cannot be un-leaked by editing code — it needs rotation by a human
or system with access to the real credential. A missing auth check cannot be safely
auto-added without knowing your intended auth scheme. Claiming full automation on
these would be dishonest and would fall apart under any technical question. Instead:

- **Deterministic fixes** — applied automatically via Semgrep's `fix`/`fix-regex`
  key or a dependency version bump. No LLM involved, fully reproducible.
- **LLM-assisted fixes** — for structurally complex findings. A patch is generated,
  applied to a backup copy, tested, and only kept if verification passes.
- **Manual-required** — never touched. Flagged with a specific, actionable reason.

This mirrors the same shape as Semgrep's own commercial Autofix (public beta,
2026): rule-defined deterministic fixes for the simple cases, LLM-generated patches
with breaking-change analysis for the complex ones, human review for anything
structurally risky. You're building an open version of that pattern.

---

## 2. Fixability classification (reference for the classifier module)

| Finding | CWE | Strategy | Fix mechanism |
|---|---|---|---|
| Dependency has known `fixed_version` (OSV) | — | Deterministic | Bump version in requirements.txt |
| Dependency vulnerable, no fix published yet | — | Manual-required | Flag, no safe target version exists |
| Hardcoded secret found | CWE-798 | Hybrid | Auto: extract to env var + `.env.example` (name only). Always also flag: "credential exposed — rotate it" |
| `requests(..., verify=False)` | CWE-295 | Deterministic | `fix-regex` |
| `app.run(debug=True)` | CWE-489 | Deterministic | `fix` |
| JWT signature/algorithm check disabled | CWE-347 | Deterministic | `fix-regex` |
| `random` module used for tokens/passwords | CWE-330 | Deterministic | `fix-regex` (import + call swap for the common pattern) |
| SQL built by string concat/f-string | CWE-89 | LLM-assisted | Patch to parameterized query, test-gated |
| `subprocess(..., shell=True)` with non-literal arg | CWE-78 | LLM-assisted | Patch to arg-list form, test-gated |
| Weak password hash (md5/sha1) | CWE-916 | LLM-assisted | Patch to bcrypt/argon2, test-gated |
| Missing auth on sensitive route | CWE-862 | Manual-required | Flag — cannot safely infer auth scheme |
| `eval`/`exec`/`pickle.loads` on non-literal | CWE-94/502 | Manual-required | Flag — too context-dependent to auto-rewrite |
| CORS wildcard + credentials | CWE-942 | Manual-required | Flag — tool doesn't know legitimate origins |

---

## 3. Safety pattern (applies to every auto-attempted fix)

```
1. Backup the file (in-memory or temp copy)
2. Apply the fix (deterministic rewrite or LLM patch)
3. Sanity check: file still parses (ast.parse for .py)
   → fails: revert immediately, log FIX_FAILED
4. Re-run ONLY the specific check that flagged this finding
   (one Semgrep rule, one OSV package, or gitleaks on that file)
   → still flags: revert, log FIX_FAILED
5. If the target project has a detectable test suite, run it
   → fails: revert, log FIX_FAILED
6. All checks pass → keep the change, log a RemediationAttempt with the
   diff, iteration number, strategy used, and outcome = RESOLVED
```

Hard rules:
- `supplyguard scan` never modifies files. `supplyguard fix` is the only command
  that does, and only after this pipeline.
- Fixes are applied to the local working tree / a local branch. The tool never
  auto-pushes or auto-merges to a remote. A human reviews and pushes.
- Every applied fix has a stored diff. Nothing is "trust me, it's fixed."

---

## 4. Remediation loop

```python
def remediate(project_path, max_iterations=5, dry_run=False, use_llm=True):
    history = []
    for iteration in range(max_iterations):
        findings = full_scan(project_path)
        auto_fixable = [f for f in findings if classify(f) != MANUAL_REQUIRED]
        if not auto_fixable:
            break
        resolved_this_round = 0
        for finding in auto_fixable:
            if finding.strategy == LLM_ASSISTED and not use_llm:
                continue
            outcome = attempt_fix(finding, dry_run=dry_run)
            if outcome == "RESOLVED":
                resolved_this_round += 1
        history.append({"iteration": iteration, "resolved": resolved_this_round})
        if resolved_this_round == 0:
            break  # no progress — stop rather than loop forever
    final_findings = full_scan(project_path)
    return build_final_report(final_findings, history)
```

Terminates when either nothing auto-fixable remains, or an iteration makes zero
progress (stubborn finding, e.g. a fix that keeps failing verification). The final
report always separates: resolved / fix-attempted-but-failed / manual-required —
so "no issues left to resolve" means "no issues left that this tool can safely
resolve on its own," which is the honest and correct framing.

---

## 5. Updated repo layout (new/changed only)

```
supplyguard/
├── remediation/
│   ├── __init__.py
│   ├── classifier.py       # FixStrategy enum + classify(finding)
│   ├── deterministic_fixer.py   # semgrep --autofix, OSV version bumps
│   ├── llm_fixer.py         # pluggable LLM patch generation (Anthropic default)
│   ├── verifier.py          # backup / apply / sanity-check / rescan / revert
│   └── loop.py               # orchestration described above
├── models.py                 # + RemediationAttempt table
├── cli.py                    # + `supplyguard fix` command
├── web/
│   ├── routes.py             # + /scan/<id>/remediation route
│   └── templates/
│       └── remediation.html  # diff view + iteration timeline
tests/
├── test_classifier.py
├── test_deterministic_fixer.py
├── test_llm_fixer.py
└── test_remediation_loop.py
```

---

## 6. AGENTS.md — add this section (append to the existing file)

```markdown
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
```

---

## 7. Mission prompts — Stage 3 (new)

### Mission 5 — Remediation classifier + deterministic fixer + verifier

```
Build the deterministic remediation path for SupplyGuard.

Create supplyguard/remediation/classifier.py:
- FixStrategy enum: DETERMINISTIC, LLM_ASSISTED, MANUAL_REQUIRED, HYBRID
- classify(finding: Finding) -> FixStrategy implementing exactly the
  mapping in this table (use it verbatim, don't reinterpret it):
  [paste the fixability table from section 2 of this doc]

Create supplyguard/remediation/verifier.py:
- A context manager or function apply_with_verification(file_path,
  patch_fn, check_fn) that: backs up the file, calls patch_fn to apply the
  change, confirms the file still parses (ast.parse for .py files), calls
  check_fn (which re-runs only the specific detector for this finding) to
  confirm the finding is resolved, runs the project's test suite if one is
  detected (look for a tests/ dir + pytest availability), and reverts to
  the backup if any step fails. Returns an outcome enum: RESOLVED,
  FIX_FAILED, SKIPPED.

Create supplyguard/remediation/deterministic_fixer.py:
- fix_dependency(finding) -> outcome: bumps the package version in
  requirements.txt to the OSV-reported fixed_version, wrapped in
  apply_with_verification
- fix_sast_deterministic(finding) -> outcome: runs `semgrep --autofix
  --config=<the specific rule file>` scoped to just this finding's rule
  ID and file, wrapped in apply_with_verification

Add `fix:` or `fix-regex:` keys to the existing rules in
supplyguard/sast/rules/ai-code-smells.yml for exactly the rules marked
Deterministic in the classification table (verify=False, debug=True, JWT
check disabled, random-for-tokens) — research the correct current
fix/fix-regex syntax for each.

Write tests in tests/test_classifier.py and tests/test_deterministic_fixer.py,
including a test that a MANUAL_REQUIRED finding never reaches a fixer
function even if someone calls the loop incorrectly. Show me the
Implementation Plan first.
```

### Mission 6 — LLM-assisted fixer + remediation loop + `supplyguard fix`

```
Build the LLM-assisted remediation path and the full remediate-and-reloop
CLI command for SupplyGuard.

Create supplyguard/remediation/llm_fixer.py:
- An abstract PatchProvider interface with one method:
  generate_patch(snippet: str, cwe: str, message: str, context_before:
  str, context_after: str) -> str (returns a minimal replacement snippet,
  not a full file)
- An AnthropicPatchProvider implementation using the Anthropic API (model
  configurable via env var, default to a current Claude model — check
  docs for the current model string rather than hardcoding an old one).
  API key read from ANTHROPIC_API_KEY env var, never hardcoded.
- The prompt template must explicitly instruct: change only what's
  necessary to fix the specific CWE, preserve function signatures and
  variable names where possible, and return one sentence explaining the
  fix for the audit log
- fix_llm_assisted(finding, provider) -> outcome: generates the patch,
  applies it via apply_with_verification from Mission 5's verifier

Create supplyguard/remediation/loop.py:
- remediate(project_path, max_iterations=5, dry_run=False, use_llm=True)
  implementing the loop from section 4 of the build plan doc (paste it in
  full) — dispatches each finding to the right fixer based on
  classify(), tracks per-iteration progress, stops on zero-progress or
  max_iterations, returns a final report distinguishing resolved /
  fix-failed / manual-required

Add `supplyguard fix <path> [--dry-run] [--max-iterations N] [--no-llm]`
to cli.py. --dry-run shows what would be attempted without writing
anything. Persist every RemediationAttempt to the DB with its diff.

Show me the Implementation Plan before starting — I want to see the exact
Anthropic API call structure and the exact prompt template before you
implement it. Once built, run `supplyguard fix .` in --dry-run mode
against this project's own repo and show me the Walkthrough.
```

---

## 8. Updated Stage 4 (was Stage 3) — Dashboard + demo app

### Mission 7 — Dashboard, now with a Remediation view

```
Extend the SupplyGuard dashboard (built in the previous mission) with a
remediation view.

Add GET /scan/<id>/remediation:
- A timeline showing risk score per iteration (line chart, Chart.js)
- Three counters: Resolved / Fix Failed / Manual Required
- For every RemediationAttempt: a collapsible diff view (before/after,
  syntax highlighted if easy, plain text diff if not), the strategy used,
  and the one-sentence explanation from the LLM fixer where applicable
- For every Manual Required finding: the specific reason it wasn't
  auto-touched, shown clearly, not just "manual"

Verify by running a full `supplyguard fix` against the vulnerable demo app
(built in the next mission — coordinate or stub sample data if it isn't
ready yet), opening the dashboard in the browser, and screenshotting the
remediation view for the Walkthrough.
```

### Mission 8 — Vulnerable demo app (needs a minimal test suite now) + CI

```
Build examples/vulnerable-demo-app/ — a small Flask app that trips every
rule in the classification table (SQL string concat, hardcoded fake key,
missing auth on an admin route, one real outdated dependency with a
confirmed OSV hit, debug=True, subprocess shell=True, md5 password hash,
JWT verification disabled, CORS wildcard with credentials, random-based
token generation, eval on user input).

Also write a minimal tests/ suite for this demo app (a handful of pytest
tests: app starts, key routes return expected status codes) — this is
required so the remediation verifier has something concrete to check
fixes against for this demo.

Run `supplyguard fix examples/vulnerable-demo-app` end to end and confirm:
deterministic and LLM-assisted findings get resolved and verified, the
manual-required findings (missing auth, eval, CORS) are correctly left
untouched with clear reasons, and the final risk score drops accordingly.
Show me the before/after risk score and the full findings breakdown in
the Walkthrough.

Then create .github/workflows/supplyguard-ci.yml: runs `supplyguard scan`
(read-only) on every push and fails the build above a risk threshold.
Keep `fix` as a manually-triggered workflow_dispatch job, not automatic on
every push — auto-remediation on every commit is a scope decision worth
being deliberate about, not a default.
```

### Mission 9 — README + docs

```
Write README.md:
- Pitch: 2026 Omdia/Docker survey of 400 security professionals found 39%
  struggle to remediate vulnerabilities quickly and 35% are specifically
  worried about AI-generated vulnerable code; industry data separately
  shows AI-assisted codebases seeing roughly a tenfold rise in flagged
  security findings. SupplyGuard doesn't just report that gap, it closes
  the mechanically-safe part of it automatically.
- Architecture diagram (mermaid): scan → classify → fix (deterministic /
  LLM-assisted / manual-required) → verify → loop → dashboard
- The fixability table from section 2 of the build plan, verbatim — this
  is the section that shows you thought about the boundary, not just the
  automation
- Quickstart: `supplyguard scan .` vs `supplyguard fix . --dry-run` vs
  `supplyguard fix .`
- Explicit "what this tool will never do" section: never auto-push/merge
  to remote, never touch manual-required findings, never fix a leaked
  secret's exposure (only the code pattern around it)
- MIT license, badges

Write docs/architecture.md with implementation detail, including the full
verifier safety sequence, for anyone extending it.
```

---

## 9. Resume bullet (v2)

> Built SupplyGuard, a self-remediating software supply-chain security
> tool: unifies SBOM generation (CycloneDX), OSS vulnerability correlation
> (OSV.dev), secrets detection (Gitleaks), and a custom CWE-mapped Semgrep
> rule pack into a weighted risk score, then automatically remediates
> findings via a classify → fix → verify → rescan loop — deterministic
> Semgrep autofixes for simple cases, LLM-generated and test-gated patches
> for structural ones, and explicit human hand-off for anything requiring
> judgment (missing auth, leaked-credential rotation). Every fix is
> verified against a rollback-on-failure safety check and logged with a
> full diff audit trail before reaching a local branch for human review.
