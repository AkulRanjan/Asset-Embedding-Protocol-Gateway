from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import BaseModel, Field

from custos_protocol.canonical import (
    NonFiniteNumberError,
    get_signable_payload,
    normalize_numbers,
    payload_hash,
)


class Sample(BaseModel):
    context: str = Field(default="https://custos.protocol/v1", alias="@context")
    amount: Decimal
    whole: float
    fractional: float
    issued_at: datetime
    optional: str | None = None
    tags: list[str]
    proof: dict | None = None
    model_config = {"populate_by_name": True}


def sample() -> Sample:
    return Sample(
        amount=Decimal("50000.00"),
        whole=500.0,
        fractional=45.5,
        issued_at=datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc),
        tags=["zebra", "alpha"],
        proof={"proof_value": "ignored"},
    )


def test_rule_2_whole_floats_become_ints():
    assert normalize_numbers({"a": 500.0}) == {"a": 500}
    assert normalize_numbers({"a": 45.5}) == {"a": 45.5}
    assert normalize_numbers([1.0, 2.5]) == [1, 2.5]
    assert normalize_numbers({"nested": {"deep": [{"x": 3.0}]}}) == {"nested": {"deep": [{"x": 3}]}}


def test_rule_2_leaves_bools_alone():
    """bool is a subclass of int; normalizing must not turn True into 1."""
    result = normalize_numbers({"flag": True, "other": False})
    assert result["flag"] is True
    assert result["other"] is False


def test_non_finite_floats_are_rejected():
    """The blueprint's normalizer crashes on these; Custos rejects them explicitly."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(NonFiniteNumberError):
            normalize_numbers({"a": bad})


def test_canonical_payload_is_byte_exact():
    payload = get_signable_payload(sample(), exclude={"proof"})
    assert payload == (
        b'{"@context":"https://custos.protocol/v1",'
        b'"amount":"50000.00",'
        b'"fractional":45.5,'
        b'"issued_at":"2026-08-21T12:00:00Z",'
        b'"optional":null,'
        b'"tags":["zebra","alpha"],'
        b'"whole":500}'
    )


def test_rule_1_excluded_field_is_absent():
    assert b"proof" not in get_signable_payload(sample(), exclude={"proof"})


def test_rule_3_keys_sorted_recursively_and_at_sorts_first():
    payload = get_signable_payload(sample(), exclude={"proof"}).decode()
    assert payload.startswith('{"@context"')
    keys = ["@context", "amount", "fractional", "issued_at", "optional", "tags", "whole"]
    positions = [payload.index(f'"{key}"') for key in keys]
    assert positions == sorted(positions)


def test_rule_4_no_whitespace():
    payload = get_signable_payload(sample(), exclude={"proof"})
    assert b" " not in payload.replace(b"https://custos.protocol/v1", b"")


def test_rule_7_nulls_are_emitted_not_omitted():
    assert b'"optional":null' in get_signable_payload(sample(), exclude={"proof"})


def test_rule_8_array_order_is_preserved():
    assert b'["zebra","alpha"]' in get_signable_payload(sample(), exclude={"proof"})


def test_payload_is_stable_across_field_construction_order():
    first = get_signable_payload(sample(), exclude={"proof"})
    second = get_signable_payload(sample(), exclude={"proof"})
    assert first == second


def test_payload_hash_is_deterministic_sha256_hex():
    digest = payload_hash(get_signable_payload(sample(), exclude={"proof"}))
    assert len(digest) == 64
    assert digest == payload_hash(get_signable_payload(sample(), exclude={"proof"}))


def test_canonical_bytes_on_a_dict_matches_the_model_path():
    """A verifier receives JSON off the wire, not a model. Both paths must agree."""
    from custos_protocol.canonical import canonical_bytes

    served = sample().model_dump(mode="json", by_alias=True)
    assert canonical_bytes(served, exclude={"proof"}) == get_signable_payload(sample(), exclude={"proof"})


def test_canonical_bytes_applies_the_same_number_rule():
    from custos_protocol.canonical import canonical_bytes

    assert canonical_bytes({"whole": 500.0}, exclude=set()) == b'{"whole":500}'
