# Vulnerable Demo Application

This directory contains a deliberately vulnerable Flask application created for testing and demonstrating **SupplyGuard**'s multi-signal scanning and automated remediation capabilities.

## Included Vulnerabilities & Misconfigurations

| Vulnerability Category | CWE | File / Location | Fix Strategy |
|---|---|---|---|
| Outdated Dependency (`requests==2.25.1`) | Multiple | `requirements.txt` | **Deterministic** (bump version) |
| Hardcoded Fake API Key | CWE-798 | `app.py:15` | **Hybrid** (env extract + rotation flag) |
| SQL Injection (String formatting) | CWE-89 | `app.py:27` | **LLM-assisted** (parameterized query) |
| Unprotected Admin Delete Route | CWE-862 | `app.py:33` | **Manual-required** (needs auth scheme) |
| Insecure Subprocess (`shell=True`) | CWE-78 | `app.py:42` | **LLM-assisted** (arg list form) |
| Disabled TLS Verification (`verify=False`) | CWE-295 | `app.py:48` | **Deterministic** (Semgrep autofix) |
| Weak Password Hash (`MD5`) | CWE-916 | `app.py:55` | **LLM-assisted** (upgrade hash) |
| Unverified JWT Decode | CWE-347 | `app.py:62` | **Deterministic** (Semgrep autofix) |
| Insecure Random Token Generation | CWE-330 | `app.py:68` | **Deterministic** (swap to `secrets`) |
| Dynamic Code Execution (`eval()`) | CWE-94 | `app.py:75` | **Manual-required** (too contextual) |
| CORS Wildcard + Credentials | CWE-942 | `app.py:82` | **Manual-required** (requires allowlist) |
| Flask Debug Mode Enabled | CWE-489 | `app.py:88` | **Deterministic** (Semgrep autofix) |

## Scanning and Remediating with SupplyGuard

```bash
# 1. Run a read-only assessment
supplyguard scan examples/vulnerable-demo-app

# 2. Preview what SupplyGuard would auto-fix
supplyguard fix examples/vulnerable-demo-app --dry-run

# 3. Apply automated fixes and verify
supplyguard fix examples/vulnerable-demo-app
```
