"""Unit tests for the 10 AI-code-smell SAST rules (vulnerable vs safe snippets)."""

from pathlib import Path

from supplyguard.sast.scanner import run_sast


def test_rule_1_sql_injection(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_sql.py"
    vuln_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("sql-injection" in f.rule_id for f in findings)

    # Safe version
    vuln_file.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("sql-injection" in f.rule_id for f in findings)


def test_rule_2_unprotected_admin_route(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_route.py"
    vuln_file.write_text(
        '@app.route("/admin/delete", methods=["DELETE"])\ndef delete_user():\n    pass\n',
        encoding="utf-8",
    )
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("unprotected-admin" in f.rule_id for f in findings)

    # Safe version with auth decorator
    vuln_file.write_text(
        '@app.route("/admin/delete", methods=["DELETE"])\n@login_required\ndef delete_user():\n    pass\n',
        encoding="utf-8",
    )
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("unprotected-admin" in f.rule_id for f in findings)


def test_rule_3_unsafe_eval(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_eval.py"
    vuln_file.write_text('result = eval(user_input)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("eval-exec" in f.rule_id for f in findings)

    # Safe version with literal
    vuln_file.write_text('result = eval("1 + 1")\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("eval-exec" in f.rule_id for f in findings)


def test_rule_4_subprocess_shell_true(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_subproc.py"
    vuln_file.write_text('subprocess.run(cmd_string, shell=True)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("subprocess-shell" in f.rule_id for f in findings)

    # Safe version with shell=False
    vuln_file.write_text('subprocess.run(["ls", "-l"], shell=False)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("subprocess-shell" in f.rule_id for f in findings)


def test_rule_5_requests_verify_false(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_req.py"
    vuln_file.write_text('requests.get("https://example.com", verify=False)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("verify-false" in f.rule_id for f in findings)

    # Safe version
    vuln_file.write_text('requests.get("https://example.com", verify=True)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("verify-false" in f.rule_id for f in findings)


def test_rule_6_flask_debug_true(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_debug.py"
    vuln_file.write_text('app.run(host="0.0.0.0", debug=True)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("debug-true" in f.rule_id for f in findings)

    # Safe version
    vuln_file.write_text('app.run(host="0.0.0.0", debug=False)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("debug-true" in f.rule_id for f in findings)


def test_rule_7_weak_hash_md5(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_hash.py"
    vuln_file.write_text('token = hashlib.md5(password.encode()).hexdigest()\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("weak-hash" in f.rule_id for f in findings)

    # Safe version with sha256
    vuln_file.write_text('token = hashlib.sha256(password.encode()).hexdigest()\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("weak-hash" in f.rule_id for f in findings)


def test_rule_8_jwt_unverified_decode(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_jwt.py"
    vuln_file.write_text('payload = jwt.decode(token, verify=False)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("jwt-unverified" in f.rule_id for f in findings)

    # Safe version
    vuln_file.write_text('payload = jwt.decode(token, key="secret", verify=True)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("jwt-unverified" in f.rule_id for f in findings)


def test_rule_9_cors_wildcard_credentials(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_cors.py"
    vuln_file.write_text(
        'resp.headers["Access-Control-Allow-Origin"] = "*"\n'
        'resp.headers["Access-Control-Allow-Credentials"] = "true"\n',
        encoding="utf-8",
    )
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("cors-wildcard" in f.rule_id for f in findings)

    # Safe version
    vuln_file.write_text(
        'resp.headers["Access-Control-Allow-Origin"] = "https://app.example.com"\n'
        'resp.headers["Access-Control-Allow-Credentials"] = "true"\n',
        encoding="utf-8",
    )
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("cors-wildcard" in f.rule_id for f in findings)


def test_rule_10_insecure_random_token(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln_random.py"
    vuln_file.write_text('auth_token = "".join(random.choice("abc") for _ in range(16))\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert any("random-token" in f.rule_id for f in findings)

    # Safe version with secrets
    vuln_file.write_text('auth_token = secrets.token_hex(16)\n', encoding="utf-8")
    findings = run_sast(tmp_path, allow_fallback=True)
    assert not any("random-token" in f.rule_id for f in findings)
