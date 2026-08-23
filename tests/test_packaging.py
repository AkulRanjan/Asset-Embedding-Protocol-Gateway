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
