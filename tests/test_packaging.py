"""Guards against shipping a wheel without its non-Python assets."""

from importlib.metadata import version
from importlib.resources import files

import supplyguard


def test_web_assets_are_packaged() -> None:
    web = files("supplyguard.web")
    for asset in ("templates/base.html", "templates/dashboard.html", "static/css/style.css", "static/js/dashboard.js"):
        assert web.joinpath(asset).is_file(), asset


def test_semgrep_rules_are_packaged() -> None:
    assert files("supplyguard.sast").joinpath("rules/ai-code-smells.yml").is_file()


def test_single_source_version() -> None:
    assert supplyguard.__version__ == version("supplyguard")
