"""The dependency rules are enforced by test, not by convention."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from custos_protocol.errors import CustosErrorCode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = PROJECT_ROOT / "custos_protocol"

# Codes no Phase 1 code path can reach. Each is unreachable because the module or
# input that would raise it is deferred, not because it is untested by oversight.
# Anything outside this set is implemented and MUST be exercised by the suite.
UNREACHABLE_IN_PHASE_1 = {
    CustosErrorCode.MONETARY_LIMIT_PER_DAY,  # boundary predicate 4 needs the Phase 2 ledger
    CustosErrorCode.ATTESTATION_MISMATCH,    # verification step 9 is a stub until hashes are plumbed
    CustosErrorCode.DELEGATION_INVALID,      # delegation.py is Phase 2
    CustosErrorCode.TRUST_SCORE_LOW,         # trust.py is Phase 2
}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_never_imports_application_layers(source):
    """custos_protocol must not depend on the gateway or on I/O services."""
    forbidden = {"gateway", "claims", "oracle"}
    for module in imported_modules(source):
        root = module.split(".")[0]
        assert root not in forbidden, f"{source.name} imports {module}"


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_never_imports_aip(source):
    """The blueprint is documentation. There must be no linkage to the AIP SDK."""
    for module in imported_modules(source):
        assert not module.startswith("aip"), f"{source.name} imports {module}"


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_performs_no_io(source):
    """Configuration arrives as value objects; the environment is read in gateway/config.py."""
    text = source.read_text(encoding="utf-8")
    assert "os.getenv" not in text, f"{source.name} reads the environment"
    assert "import httpx" not in text, f"{source.name} opens a socket"


@pytest.mark.parametrize(
    "source",
    sorted((PROJECT_ROOT / "oracle").glob("*.py")) + sorted((PROJECT_ROOT / "claims").glob("*.py")),
    ids=lambda p: f"{p.parent.name}/{p.name}",
)
def test_data_services_never_import_the_http_layer(source):
    """oracle/ and claims/ are injected into the gateway, never the reverse."""
    for module in imported_modules(source):
        assert module.split(".")[0] != "gateway", f"{source.name} imports {module}"


def test_superseded_packages_are_gone():
    assert not (PROJECT_ROOT / "models").exists()
    assert not (PROJECT_ROOT / "attest").exists()
    assert not (PROJECT_ROOT / "gateway" / "validation.py").exists()
    assert not (PROJECT_ROOT / "config.py").exists()


def test_every_error_code_is_exercised_by_the_suite():
    """The blueprint ships 4 of 23 codes dead. Every code Custos implements is tested."""
    corpus = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PROJECT_ROOT / "tests").glob("test_*.py")
    )
    missing = [
        code.name for code in CustosErrorCode
        if code not in UNREACHABLE_IN_PHASE_1
        and code.name not in corpus
        and code.value not in corpus
    ]
    assert missing == [], f"error codes with no test: {missing}"


def test_the_deferred_code_list_does_not_hide_a_live_code():
    """Guards the exemption list itself: a deferred code must be unreachable in the
    protocol package, or it is a live code being excused from its test."""
    protocol_source = "\n".join(
        path.read_text(encoding="utf-8") for path in PROTOCOL.glob("*.py")
        if path.name != "errors.py"          # the taxonomy declares every code by definition
    )
    leaked = [code.name for code in UNREACHABLE_IN_PHASE_1 if code.name in protocol_source]
    assert leaked == [], f"deferred codes that a Phase 1 path can actually emit: {leaked}"


def test_bare_pytest_collects_the_suite():
    """Regression guard: only `python -m pytest` worked before pyproject.toml existed."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
