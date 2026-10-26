"""Unit tests for LLM-assisted remediation fixer and patch providers."""

from pathlib import Path

from supplyguard.remediation.llm_fixer import (
    AnthropicPatchProvider,
    PatchProvider,
    fix_llm_assisted,
)
from supplyguard.remediation.verifier import FixOutcome
from supplyguard.sast.scanner import SastFinding


class MockCustomPatchProvider(PatchProvider):
    def generate_patch(
        self,
        snippet: str,
        cwe: str,
        message: str,
        context_before: str = "",
        context_after: str = "",
    ) -> tuple[str, str]:
        # Simple mock converting f-string query to parameterized query
        if "execute" in snippet:
            return 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', "Converted SQL to parameterized query."
        return snippet, "Unchanged"


def test_fix_llm_assisted_success(tmp_path: Path) -> None:
    test_file = tmp_path / "db.py"
    test_file.write_text(
        'def get_user(cursor, user_id):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        '    return cursor.fetchone()\n',
        encoding="utf-8",
    )

    finding = SastFinding(
        file="db.py",
        line=2,
        rule_id="ai-sql-injection-concat",
        severity="HIGH",
        cwe="CWE-89",
        message="SQL concatenation",
    )

    provider = MockCustomPatchProvider()
    outcome, diff, explanation = fix_llm_assisted(tmp_path, finding, provider)

    assert outcome == FixOutcome.RESOLVED
    assert "parameterized query" in explanation.lower()
    assert "-    cursor.execute(f\"SELECT" in diff
    assert "+    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))" in diff
    assert "f\"SELECT" not in test_file.read_text(encoding="utf-8")


def test_anthropic_patch_provider_heuristic_fallback() -> None:
    # When no API key is provided, verify graceful heuristic fallback
    provider = AnthropicPatchProvider(api_key=None)
    snippet = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    replacement, explanation = provider.generate_patch(snippet, "CWE-89", "SQL injection")

    assert "parameterized" in explanation.lower()
    assert "%s" in replacement


class _AlwaysPatch(PatchProvider):
    def generate_patch(self, snippet, cwe, message, context_before="", context_after=""):
        return snippet.replace("hashlib.md5", "hashlib.sha256"), "Use SHA-256."


class _PatchThatAddsShellTrue(PatchProvider):
    def generate_patch(self, snippet, cwe, message, context_before="", context_after=""):
        indent = snippet[: len(snippet) - len(snippet.lstrip())]
        return f"{indent}subprocess.run(cmd, shell=True)", "Replaced hash with shell call."


def _weak_hash_finding(line: int) -> SastFinding:
    return SastFinding(
        file="h.py", line=line, rule_id="ai-weak-hash-md5-sha1", cwe="CWE-916",
        severity="MEDIUM", message="weak hash",
    )


def test_llm_patch_targets_the_flagged_line_not_the_first_match(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import hashlib\n"
        "def a(x):\n"
        "    return hashlib.md5(x).hexdigest()\n"
        "def b(x):\n"
        "    return hashlib.md5(x).hexdigest()\n",
        encoding="utf-8",
    )
    outcome, _, _ = fix_llm_assisted(tmp_path, _weak_hash_finding(5), _AlwaysPatch())

    lines = (tmp_path / "h.py").read_text(encoding="utf-8").splitlines()
    assert outcome == FixOutcome.RESOLVED
    assert "md5" in lines[2]  # line 3 untouched
    assert "sha256" in lines[4]  # line 5 (the flagged one) patched


def test_llm_patch_that_introduces_a_new_finding_is_rolled_back(tmp_path: Path) -> None:
    original = "import hashlib\nimport subprocess\ndef a(x, cmd):\n    return hashlib.md5(x).hexdigest()\n"
    (tmp_path / "h.py").write_text(original, encoding="utf-8")

    outcome, _, _ = fix_llm_assisted(tmp_path, _weak_hash_finding(4), _PatchThatAddsShellTrue())

    assert outcome == FixOutcome.FIX_FAILED
    assert (tmp_path / "h.py").read_text(encoding="utf-8") == original
