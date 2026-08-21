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
