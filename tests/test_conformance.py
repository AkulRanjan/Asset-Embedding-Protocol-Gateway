from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from custos_protocol.errors import CustosErrorCode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_DIR = PROJECT_ROOT / "conformance"
VECTORS_PATH = CONFORMANCE_DIR / "vectors.json"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vectors_file_exists_and_has_the_expected_shape():
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert "_meta" in document
    assert "vectors" in document
    assert document["_meta"]["vector_count"] == len(document["vectors"])


def test_every_vector_id_is_unique():
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    ids = [vector["id"] for vector in document["vectors"]]
    assert len(ids) == len(set(ids))


def test_every_sdk_reachable_error_code_has_a_vector():
    """E304 and E502 are gateway/oracle integration concerns verify_intent never
    emits (see generate_vectors.py's module docstring); every other code must
    have at least one vector."""
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    covered = {
        code for vector in document["vectors"]
        for code in vector.get("expected", {}).get("errors", [])
    }
    excluded = set(document["_meta"]["excluded_codes"].keys())
    all_codes = {code.value for code in CustosErrorCode}
    missing = all_codes - covered - excluded
    assert missing == set(), f"error codes with no conformance vector: {missing}"


def test_all_vectors_pass():
    run_conformance = _load_module("run_conformance", CONFORMANCE_DIR / "run_conformance.py")
    passed, total, failures = run_conformance.run()
    assert failures == []
    assert passed == total


def test_regenerating_the_vectors_is_byte_for_byte_reproducible():
    """Fixed seeds, fixed clock, fixed nonce counter: regenerating must not
    change a single byte of the committed file."""
    committed = VECTORS_PATH.read_bytes()
    result = subprocess.run(
        [sys.executable, str(CONFORMANCE_DIR / "generate_vectors.py")],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )
    try:
        assert result.returncode == 0, result.stdout + result.stderr
        regenerated = VECTORS_PATH.read_bytes()
        assert regenerated == committed, "regenerating vectors.json changed its bytes — check for a non-deterministic input (e.g. a bare datetime.now())"
    finally:
        VECTORS_PATH.write_bytes(committed)  # restore exactly, regardless of outcome
