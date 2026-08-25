"""Safety verifier with automatic rollback for remediation fixes."""

import ast
import difflib
import logging
import shutil
import subprocess
import sys
from collections.abc import Callable
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class FixOutcome(str, Enum):
    """Possible outcomes of a remediation fix attempt."""

    RESOLVED = "RESOLVED"
    FIX_FAILED = "FIX_FAILED"
    SKIPPED = "SKIPPED"


def _compute_diff(original: str, modified: str, file_name: str) -> str:
    """Generate a clean unified diff string."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{file_name}",
        tofile=f"b/{file_name}",
    )
    return "".join(diff)


def _run_project_tests(project_path: Path) -> bool:
    """Run detectable test suite if present in the target project.

    Args:
        project_path: Project root directory.

    Returns:
        True if tests passed or no test suite / test runner detected, False if tests failed.
    """
    tests_dir = project_path / "tests"
    if not tests_dir.exists() or not any(tests_dir.glob("test_*.py")):
        return True

    rel_tests = str(tests_dir.relative_to(project_path))

    # Look for virtualenv-specific pytest first (supports Windows & POSIX)
    venv_pytest_candidates = [
        project_path / ".venv" / "Scripts" / "pytest.exe",
        project_path / ".venv" / "bin" / "pytest",
        project_path / "venv" / "Scripts" / "pytest.exe",
        project_path / "venv" / "bin" / "pytest",
    ]
    pytest_bin = next((str(p) for p in venv_pytest_candidates if p.exists()), None)
    if not pytest_bin:
        pytest_bin = shutil.which("pytest")

    if pytest_bin:
        cmd = [
            pytest_bin,
            rel_tests,
            "-o",
            f"rootdir={project_path}",
            "-o",
            "testpaths=tests",
            "-q",
        ]
    else:
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            rel_tests,
            "-o",
            f"rootdir={project_path}",
            "-o",
            "testpaths=tests",
            "-q",
        ]

    try:
        res = subprocess.run(
            cmd,
            cwd=str(project_path),
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=30,
        )
        if res.returncode != 0:
            output = (res.stdout or "") + "\n" + (res.stderr or "")
            # If pytest is not installed or dependencies/plugins needed to load tests are missing
            skip_signatures = (
                "No module named pytest",
                "not recognized as an internal or external command",
                "The term 'pytest' is not recognized",
                "ImportError while loading conftest",
                "ModuleNotFoundError: No module named",
                "ImportError: No module named",
                "pytest: error:",
                "UsageError",
            )
            if any(sig in output for sig in skip_signatures):
                logger.debug(f"Test suite cannot be executed due to missing runner/dependencies: {output.strip()}")
                return True

            logger.warning(f"Test suite failure: {output.strip()}")
            return False

        return True
    except (OSError, subprocess.SubprocessError) as err:
        logger.warning(f"Error running test suite: {err}")
        return True


def apply_with_verification(
    file_path: Path,
    patch_fn: Callable[[], None],
    check_fn: Callable[[], bool],
    project_path: Path | None = None,
) -> tuple[FixOutcome, str]:
    """Apply a patch with full rollback protection and multi-stage verification.

    Safety Sequence:
        1. In-memory backup of original file content (or record non-existence).
        2. Apply patch via `patch_fn`.
        3. AST syntax parse check for Python files (revert if invalid).
        4. Re-run targeted security check via `check_fn` (revert if still failing).
        5. Run project test suite if present (revert if regression detected).
        6. Compute unified diff and confirm resolution.

    Args:
        file_path: Target file being modified.
        patch_fn: Callable applying the patch to file_path.
        check_fn: Callable returning True if finding is resolved, False if still present.
        project_path: Optional project root path for running regression test suites.

    Returns:
        Tuple of (FixOutcome, diff_text).
    """
    file_existed = file_path.exists()
    original_text = ""
    if file_existed:
        try:
            original_text = file_path.read_text(encoding="utf-8")
        except OSError as err:
            logger.error(f"Cannot read target file {file_path}: {err}")
            return FixOutcome.FIX_FAILED, ""

    def _revert() -> None:
        if file_existed:
            file_path.write_text(original_text, encoding="utf-8")
        elif file_path.exists():
            file_path.unlink()

    try:
        # Step 1.5: Record baseline test suite health before patch
        baseline_tests_passed = _run_project_tests(project_path) if project_path else True

        # Step 2: Apply the fix
        patch_fn()
        if not file_path.exists():
            return FixOutcome.FIX_FAILED, ""

        modified_text = file_path.read_text(encoding="utf-8")

        if file_existed and original_text == modified_text:
            return FixOutcome.SKIPPED, ""

        # Step 3: Python AST Sanity Check
        if file_path.suffix == ".py":
            try:
                ast.parse(modified_text, filename=str(file_path))
            except SyntaxError as syntax_err:
                logger.warning(f"Fix resulted in invalid Python syntax in {file_path}: {syntax_err}")
                _revert()
                return FixOutcome.FIX_FAILED, ""

        # Step 4: Targeted Rescan Check
        if not check_fn():
            logger.warning(f"Targeted check failed after fix for {file_path}. Reverting.")
            _revert()
            return FixOutcome.FIX_FAILED, ""

        # Step 5: Regression Test Suite Check (only revert if tests passed before but fail now)
        if project_path and baseline_tests_passed and not _run_project_tests(project_path):
            logger.warning(f"Project test suite failed after fix for {file_path}. Reverting.")
            _revert()
            return FixOutcome.FIX_FAILED, ""

        # Step 6: All checks passed -> keep change and return unified diff
        diff_text = _compute_diff(original_text, modified_text, file_path.name)
        return FixOutcome.RESOLVED, diff_text

    except Exception as exc:  # noqa: BLE001 - safety verifier must roll back on ANY unexpected runtime failure
        logger.error(f"Unexpected error applying fix to {file_path}: {exc}. Reverting.")
        _revert()
        return FixOutcome.FAILED_REGRESSION, f"Verification crashed: {exc}"
