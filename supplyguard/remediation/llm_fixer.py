"""LLM-assisted remediation for complex findings (SQL injection, subprocess, weak hash)."""

import logging
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path

from supplyguard.remediation.verifier import FixOutcome, apply_with_verification
from supplyguard.sast.scanner import SastFinding, run_sast

logger = logging.getLogger(__name__)

DEFAULT_LLM_MODEL = os.environ.get("SUPPLYGUARD_LLM_MODEL", "claude-sonnet-4-20250514")


class PatchProvider(ABC):
    """Abstract interface for LLM patch generation providers."""

    @abstractmethod
    def generate_patch(
        self,
        snippet: str,
        cwe: str,
        message: str,
        context_before: str = "",
        context_after: str = "",
    ) -> tuple[str, str]:
        """Generate a secure replacement patch and audit explanation.

        Args:
            snippet: The vulnerable code block/line.
            cwe: The target CWE identifier.
            message: Finding description.
            context_before: Surrounding lines before snippet.
            context_after: Surrounding lines after snippet.

        Returns:
            Tuple of (replacement_snippet, one_sentence_explanation).
        """


class AnthropicPatchProvider(PatchProvider):
    """Patch provider using the Anthropic API (Claude)."""

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or DEFAULT_LLM_MODEL

    def generate_patch(
        self,
        snippet: str,
        cwe: str,
        message: str,
        context_before: str = "",
        context_after: str = "",
    ) -> tuple[str, str]:
        """Call Anthropic API to generate a targeted fix."""
        if not self.api_key:
            return self._heuristic_fallback(snippet, cwe, message)

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)

            prompt = f"""You are an automated code security remediation agent.
Fix the following vulnerable Python code snippet to remediate {cwe}: {message}.

RULES:
1. Change ONLY what is strictly necessary to resolve the vulnerability.
2. Preserve existing variable names, function signatures, and coding style.
3. Output format:
   First line: EXPLANATION: <One concise sentence explaining the fix>
   Following: The replacement code inside a ```python ``` codeblock.

Context before snippet:
{context_before}

Vulnerable snippet to replace:
{snippet}

Context after snippet:
{context_after}
"""
            response = client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = response.content[0].text if response.content else ""
            explanation, replacement = self._parse_llm_response(raw_text, snippet)
            return replacement, explanation

        except Exception as err:  # noqa: BLE001 - robust fallback on any Anthropic API/network failure
            logger.warning(f"Anthropic API call failed: {err}. Using rule heuristic.")
            return self._heuristic_fallback(snippet, cwe, message)

    def _parse_llm_response(self, text: str, fallback_snippet: str) -> tuple[str, str]:
        """Parse explanation and python code block from LLM response."""
        explanation = "Applied LLM-generated security patch."
        exp_match = re.search(r"EXPLANATION:\s*(.+)", text)
        if exp_match:
            explanation = exp_match.group(1).strip()

        code_match = re.search(r"```(?:python)?\s*\n(.*?)\n```", text, re.DOTALL)
        if code_match:
            return explanation, code_match.group(1)

        return explanation, fallback_snippet

    def _heuristic_fallback(self, snippet: str, cwe: str, message: str) -> tuple[str, str]:
        """Heuristic patch generator for when LLM API is unavailable."""
        # 1. SQL Injection: f-string or string concat in execute
        if "CWE-89" in cwe or "sql" in message.lower():
            # Convert execute(f"... {var} ...") to execute("... %s ...", (var,))
            fixed = re.sub(r'execute\(f["\']([^"\'\{]+)\{([a-zA-Z0-9_]+)\}([^"\']*)["\']\)', r'execute("\1%s\3", (\2,))', snippet)
            if fixed != snippet:
                return fixed, "Converted string interpolation in SQL query to parameterized query."

        # 2. Subprocess shell=True: remove shell=True and split args if string
        if "CWE-78" in cwe or "subprocess" in message.lower():
            fixed = re.sub(r",\s*shell\s*=\s*True", ", shell=False", snippet)
            if fixed != snippet:
                return fixed, "Set shell=False on subprocess invocation."

        # 3. Weak Hash MD5/SHA1 -> SHA256 or bcrypt
        if "CWE-916" in cwe or "hash" in message.lower():
            fixed = re.sub(r"hashlib\.(?:md5|sha1)\(", "hashlib.sha256(", snippet)
            if fixed != snippet:
                return fixed, "Replaced weak cryptographic hash with hashlib.sha256."

        return snippet, "No patch generated."


def fix_llm_assisted(
    project_path: Path,
    finding: SastFinding,
    provider: PatchProvider | None = None,
) -> tuple[FixOutcome, str, str]:
    """Execute LLM-assisted remediation on a structural finding with verification.

    Args:
        project_path: Target codebase root path.
        finding: SastFinding to remediate.
        provider: PatchProvider implementation.

    Returns:
        Tuple of (FixOutcome, diff_text, explanation).
    """
    target_file = project_path / finding.file
    if not target_file.exists():
        return FixOutcome.FIX_FAILED, "", "Target file not found."

    llm_provider = provider or AnthropicPatchProvider()
    lines = target_file.read_text(encoding="utf-8").splitlines()
    line_idx = max(0, finding.line - 1)

    # Extract 3 lines of context around finding
    start_ctx = max(0, line_idx - 3)
    end_ctx = min(len(lines), line_idx + 4)

    context_before = "\n".join(lines[start_ctx:line_idx])
    vulnerable_snippet = lines[line_idx] if line_idx < len(lines) else ""
    context_after = "\n".join(lines[line_idx + 1:end_ctx])

    replacement, explanation = llm_provider.generate_patch(
        snippet=vulnerable_snippet,
        cwe=finding.cwe,
        message=finding.message,
        context_before=context_before,
        context_after=context_after,
    )

    if replacement == vulnerable_snippet or not replacement:
        return FixOutcome.SKIPPED, "", "LLM generated identical or empty patch."

    # Preserve indentation if replacement lacks it
    leading_ws = ""
    if vulnerable_snippet:
        leading_ws = vulnerable_snippet[:len(vulnerable_snippet) - len(vulnerable_snippet.lstrip())]
    if leading_ws and not replacement.startswith((" ", "\t")):
        replacement_lines = [
            f"{leading_ws}{line}" if line.strip() else line
            for line in replacement.splitlines()
        ]
        replacement = "\n".join(replacement_lines)

    def _patch() -> None:
        file_content = target_file.read_text(encoding="utf-8")
        patched = file_content.replace(vulnerable_snippet, replacement, 1)
        target_file.write_text(patched, encoding="utf-8")

    def _check() -> bool:
        findings = run_sast(project_path)
        matching = [
            f for f in findings
            if f.file == finding.file and f.rule_id == finding.rule_id
        ]
        return len(matching) == 0

    outcome, diff = apply_with_verification(target_file, _patch, _check, project_path)
    return outcome, diff, explanation
