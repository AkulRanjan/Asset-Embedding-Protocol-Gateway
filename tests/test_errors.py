from __future__ import annotations

import pytest

from custos_protocol.errors import (
    ERROR_SPECS,
    CustosError,
    CustosErrorCode,
    http_status_for,
)


def test_taxonomy_has_thirty_codes():
    assert len(CustosErrorCode) == 30


def test_every_code_has_a_spec_with_status_and_description():
    for code in CustosErrorCode:
        spec = ERROR_SPECS[code]
        assert spec.http_status in {400, 401, 403, 404, 409, 422, 502, 503}
        assert spec.description, f"{code.name} has no description"


def test_code_value_and_name_shape():
    assert CustosErrorCode.INVALID_SIGNATURE.value == "CUSTOS-E100"
    assert CustosErrorCode.INVALID_SIGNATURE.name == "INVALID_SIGNATURE"
    for code in CustosErrorCode:
        assert code.value.startswith("CUSTOS-E")
        assert len(code.value) == len("CUSTOS-E100")


def test_families_are_correctly_sized():
    families: dict[str, int] = {}
    for code in CustosErrorCode:
        families[code.value[8]] = families.get(code.value[8], 0) + 1
    assert families == {"1": 7, "2": 7, "3": 7, "4": 6, "5": 3}


@pytest.mark.parametrize(
    "code,status",
    [
        (CustosErrorCode.INVALID_SIGNATURE, 401),
        (CustosErrorCode.REPLAY_DETECTED, 409),
        (CustosErrorCode.UNKNOWN_ASSET, 404),
        (CustosErrorCode.TENOR_UNSUPPORTED, 422),
        (CustosErrorCode.ORACLE_UNAVAILABLE, 503),
        (CustosErrorCode.DOWNSTREAM_UNREACHABLE, 502),
        (CustosErrorCode.CLAIM_STALE, 403),
    ],
)
def test_http_status_mapping(code, status):
    assert http_status_for(code) == status


def test_custos_error_serializes_for_an_api_response():
    error = CustosError(CustosErrorCode.YIELD_DRIFT_EXCEEDED, detail="drift 3.36% > 2.0%")
    assert error.to_dict() == {
        "error": "CUSTOS-E301",
        "error_name": "YIELD_DRIFT_EXCEEDED",
        "description": ERROR_SPECS[CustosErrorCode.YIELD_DRIFT_EXCEEDED].description,
        "detail": "drift 3.36% > 2.0%",
    }


def test_custos_error_is_raisable_and_carries_its_code():
    with pytest.raises(CustosError) as caught:
        raise CustosError(CustosErrorCode.AGENT_REVOKED)
    assert caught.value.code is CustosErrorCode.AGENT_REVOKED
