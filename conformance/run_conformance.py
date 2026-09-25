"""Reference conformance runner.

Reads `vectors.json` as plain data — every input is rebuilt from JSON via
`.model_validate()`, never reused as an in-memory Python object from the
generator — and checks that `custos_protocol.verify_intent` (for pipeline
vectors) or `custos_protocol.canonical.canonical_bytes` (for serialization
vectors) reproduces the recorded expectation exactly.

A second-language implementation is conformant when it reproduces the same
canonical bytes for every `serialization` vector and the same
passed/tier_used/errors for every other vector.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

from custos_protocol.canonical import canonical_bytes
from custos_protocol.crypto import b64_to_public_key
from custos_protocol.models import Claim, CustosEnvelope, Observation
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.trust import TrustEngine
from custos_protocol.verification import verify_intent

VECTORS_PATH = Path(__file__).with_name("vectors.json")


class ConformanceFailure(AssertionError):
    pass


def _run_pipeline_vector(vector: dict) -> None:
    envelope = CustosEnvelope.model_validate(vector["envelope"])
    public_key = b64_to_public_key(vector["verify_public_key"])
    claim = Claim.model_validate(vector["claim"]) if vector.get("claim") else None
    observation = Observation.model_validate(vector["observation"]) if vector.get("observation") else None
    now = datetime.fromisoformat(vector["now"])

    store = RevocationStore(local_only=vector.get("revocation_local_only", True))
    for entry in vector.get("revocations", []):
        subject_type = SubjectType(entry["subject_type"])
        if entry["action"] == "suspend":
            store.suspend(entry["subject_id"], subject_type, duration_seconds=entry.get("duration_seconds", 1800))
        else:
            store.revoke(entry["subject_id"], subject_type)

    trust_engine = TrustEngine()
    if vector.get("day_total_seed") is not None:
        trust_engine.record_amount(envelope.agent.id, vector["day_total_seed"], now=now)

    hmac_key = bytes.fromhex(vector["hmac_key"]) if vector.get("hmac_key") else None

    kwargs = dict(
        claim=claim, observation=observation, revocation_store=store, trust_engine=trust_engine,
        min_trust_score=vector.get("min_trust_score", 0.0), hmac_key=hmac_key,
        max_revocation_staleness_ms=vector.get("max_revocation_staleness_ms", 500),
        request_geo=vector.get("request_geo"),
        registered_frameworks=set(vector["registered_frameworks"]) if vector.get("registered_frameworks") else None,
        known_build_hashes=vector.get("known_build_hashes"),
        known_prompt_hashes=vector.get("known_prompt_hashes"),
        now=now,
    )

    if vector.get("verify_twice"):
        verify_intent(envelope, public_key, **kwargs)

    sleep_ms = vector.get("requires_sleep_ms")
    if sleep_ms:
        # The one vector where staleness is measured against the real wall
        # clock, an operational concern rather than an envelope timestamp — see
        # this vector's own description in vectors.json for why.
        time.sleep(sleep_ms / 1000)

    result = verify_intent(envelope, public_key, **kwargs)

    expected = vector["expected"]
    actual = {
        "passed": result.passed,
        "tier_used": result.tier_used.value,
        "errors": [code.value for code in result.errors],
    }
    if actual != expected:
        raise ConformanceFailure(f"{vector['id']}: expected {expected}, got {actual}")


def _run_serialization_vector(vector: dict) -> None:
    exclude = set(vector.get("exclude", []))
    actual = canonical_bytes(vector["payload_input"], exclude=exclude)
    expected = bytes.fromhex(vector["canonical_payload_hex"])
    if actual == expected:
        return
    first_diff = next((i for i in range(min(len(actual), len(expected))) if actual[i] != expected[i]),
                      min(len(actual), len(expected)))
    context = slice(max(0, first_diff - 20), first_diff + 20)
    raise ConformanceFailure(
        f"{vector['id']}: canonical payload mismatch at byte {first_diff}\n"
        f"  expected: ...{expected[context]!r}...\n"
        f"  actual:   ...{actual[context]!r}..."
    )


def run(vectors_path: Path = VECTORS_PATH) -> tuple[int, int, list[str]]:
    document = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = document["vectors"]
    failures: list[str] = []
    passed = 0
    for vector in vectors:
        try:
            if vector["category"] == "serialization":
                _run_serialization_vector(vector)
            else:
                _run_pipeline_vector(vector)
            passed += 1
        except ConformanceFailure as exc:
            failures.append(str(exc))
        except Exception as exc:  # noqa: BLE001 - a broken vector should report, not crash the run
            failures.append(f"{vector['id']}: unexpected error: {exc!r}")
    return passed, len(vectors), failures


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    passed, total, failures = run()
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    meta = document["_meta"]
    print(f"Custos Conformance Suite")
    print(f"Spec: {meta['spec_version']} | Vectors: {total} | Generated: {meta['generated_at']}")
    if failures:
        for failure in failures:
            print(f"  FAIL {failure}")
        print(f"  {passed}/{total} vectors passed")
        return 1
    print(f"  ALL {total} VECTORS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
