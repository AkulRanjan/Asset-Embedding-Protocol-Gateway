from __future__ import annotations

from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — the declared floor
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_exists_and_declares_pythonpath():
    """Bare `pytest` must resolve top-level packages; only `python -m pytest` did before."""
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["pytest"]["ini_options"]["pythonpath"] == ["."]


def test_python_floor_is_310():
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["requires-python"] == ">=3.10"


def test_console_scripts_declare_both_clis():
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = config["project"]["scripts"]
    assert scripts["custos"] == "custos_protocol.cli:cli"
    assert scripts["custos-admin"] == "gateway.admin_cli:cli"


def test_the_wheel_ships_every_first_party_package_a_console_script_needs():
    """custos-admin lives in gateway/, which imports claims/ and oracle/; a wheel
    missing any of them installs a command that dies with ModuleNotFoundError."""
    import ast

    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shipped = set(config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"])
    first_party = {path.parent.name for path in PROJECT_ROOT.glob("*/__init__.py")}

    needed = {target.split(".")[0] for target in config["project"]["scripts"].values()}
    pending = list(needed)
    while pending:
        for source in (PROJECT_ROOT / pending.pop()).glob("*.py"):
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for root in {name.split(".")[0] for name in names} & first_party - needed:
                    needed.add(root)
                    pending.append(root)

    assert needed <= shipped, f"missing from the wheel: {sorted(needed - shipped)}"
