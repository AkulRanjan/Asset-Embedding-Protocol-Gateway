"""One-liner enforcement API: protect a callable behind a real Custos verification.

Local policy enforcement with a cryptographic audit trail, not remote attestation
— the same passport signs the envelope and verifies it, so there is no second
party. Every call still produces a signed, canonically-serialized, nonce-bearing
record of what was attempted and whether it was allowed, and the boundary /
revocation / trust engines are the real gate. A compromised process holding the
private key can bypass this wrapper entirely — a property of single-process
enforcement, not a defect here.

Custos's `Action` enum is closed (borrow_against / trade / redeem / read), unlike
the reference implementation this module is modeled on (see ARCHITECTURE1.md
§18), where "action" is any function name. So `action=` is always explicit here
rather than defaulted from `func.__name__` — there is usually no sensible mapping
from an arbitrary Python name to one of the four domain actions, and guessing
wrong would either silently deny every call (that blueprint's own Trap 1) or
silently pick the wrong one.

`passport` is always a required argument, on every entry point, never minted for
the caller. Auto-minting a fresh passport per decorated instance is a documented
blueprint bug (Trap 7): trust history and revocation targets drift, and revoking
"the agent" doesn't revoke tomorrow's instance.
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, TypeVar

from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action, Claim, Observation, VerificationResult, VerificationTier
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import RevocationStore
from custos_protocol.trust import TrustEngine
from custos_protocol.verification import verify_intent

ClaimResolver = Callable[[str], "Claim | None"]
ObservationResolver = Callable[["Claim"], "Observation | None"]

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

_VALID_ON_VIOLATION = frozenset({"raise", "log", "silent"})
_BLOCKED = object()


class CustosViolation(Exception):
    """Raised by a protected callable when verification fails. Carries the full
    `VerificationResult` so a caller can inspect `errors`, `detail`, and `checks`
    rather than parsing a message string."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        codes = ", ".join(code.value for code in result.errors) or result.detail
        super().__init__(f"Custos blocked this call: {codes}")


def _build_parameters(func: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        parameters = dict(bound.arguments)
    except TypeError:
        # A signature Custos can't bind (e.g. *args-only) still gets *something*
        # recorded rather than crashing the call before verification even runs.
        parameters = dict(kwargs)
    parameters.pop("self", None)
    return parameters


def _verify(
    func: Callable,
    *,
    action: Action,
    target: str,
    tier: VerificationTier | None,
    on_violation: str,
    passport: AgentPassport,
    revocation_store: RevocationStore | None,
    trust_engine: TrustEngine | None,
    claim_resolver: ClaimResolver | None,
    observation_resolver: ObservationResolver | None,
    args: tuple,
    kwargs: dict,
) -> VerificationResult | object:
    if on_violation not in _VALID_ON_VIOLATION:
        raise ValueError(f"on_violation must be one of {sorted(_VALID_ON_VIOLATION)}, got {on_violation!r}")

    parameters = _build_parameters(func, args, kwargs)
    call_target = parameters.pop("target", None) or target

    envelope = create_envelope(passport, action, call_target, parameters, tier=tier)
    signed = sign_envelope(envelope, passport.private_key)

    # Custos has no built-in access to claims/oracle data (custos_protocol performs
    # no I/O), so Tier 1+ asset-truth is opt-in here: a caller who wants it supplies
    # resolver callables — plain functions, which may do I/O on the *caller's* side
    # — the same shape verify_intent already takes claim/observation as plain
    # values from gateway/server.py's own resolution. Without one, a value-moving
    # action still gets a real signed, tier-selected, boundary-checked envelope;
    # it just can't clear an asset-truth check it has no data for, and fails
    # closed with UNKNOWN_ASSET rather than silently skipping the check.
    claim: Claim | None = None
    observation: Observation | None = None
    if claim_resolver is not None:
        claim = claim_resolver(call_target)
        if claim is not None and observation_resolver is not None:
            observation = observation_resolver(claim)

    result = verify_intent(
        signed, passport.public_key,
        claim=claim, observation=observation,
        revocation_store=revocation_store, trust_engine=trust_engine,
    )

    if result.passed:
        return result
    if on_violation == "raise":
        raise CustosViolation(result)
    if on_violation == "log":
        logger.warning(
            "Custos blocked %s: %s", getattr(func, "__qualname__", func),
            [code.value for code in result.errors] or result.detail,
        )
    return _BLOCKED


def protect(
    func: F | None = None,
    *,
    action: Action | None = None,
    target: str = "",
    tier: VerificationTier | None = None,
    on_violation: str = "raise",
    passport: AgentPassport | None = None,
    revocation_store: RevocationStore | None = None,
    trust_engine: TrustEngine | None = None,
    claim_resolver: ClaimResolver | None = None,
    observation_resolver: ObservationResolver | None = None,
) -> F:
    """Wrap a single callable (sync or async) behind a Custos verification.

    Usable directly (`protected = protect(pay, action=Action.TRADE, passport=p)`)
    or as a decorator factory (`@protect(action=Action.TRADE, passport=p)`).

    `claim_resolver`/`observation_resolver` are optional plain functions the
    caller supplies to answer Tier 1+ asset-truth checks (`claim_resolver(target)
    -> Claim | None`, `observation_resolver(claim) -> Observation | None`); any
    I/O they do is the caller's concern, not custos_protocol's. Without them, a
    value-moving action (which auto-selects at least Tier 1) still gets a real
    signed, boundary-checked envelope — it just fails closed with
    `UNKNOWN_ASSET` rather than silently skipping the check it has no data for.
    """
    if func is None:
        return functools.partial(  # type: ignore[return-value]
            protect, action=action, target=target, tier=tier, on_violation=on_violation,
            passport=passport, revocation_store=revocation_store, trust_engine=trust_engine,
            claim_resolver=claim_resolver, observation_resolver=observation_resolver,
        )
    if action is None:
        raise TypeError("protect() requires action=<Action member>")
    if passport is None:
        raise TypeError("protect() requires passport=<AgentPassport> — Custos never mints one for you")

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            outcome = _verify(func, action=action, target=target, tier=tier, on_violation=on_violation,
                              passport=passport, revocation_store=revocation_store,
                              trust_engine=trust_engine, claim_resolver=claim_resolver,
                              observation_resolver=observation_resolver, args=args, kwargs=kwargs)
            if outcome is _BLOCKED:
                return None
            return await func(*args, **kwargs)
        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        outcome = _verify(func, action=action, target=target, tier=tier, on_violation=on_violation,
                          passport=passport, revocation_store=revocation_store,
                          trust_engine=trust_engine, claim_resolver=claim_resolver,
                          observation_resolver=observation_resolver, args=args, kwargs=kwargs)
        if outcome is _BLOCKED:
            return None
        return func(*args, **kwargs)
    return sync_wrapper  # type: ignore[return-value]


def shield(
    *,
    actions: dict[str, Action],
    passport: AgentPassport,
    target: str = "",
    tier: VerificationTier | None = None,
    on_violation: str = "raise",
    revocation_store: RevocationStore | None = None,
    trust_engine: TrustEngine | None = None,
    claim_resolver: ClaimResolver | None = None,
    observation_resolver: ObservationResolver | None = None,
) -> Callable[[type], type]:
    """Class decorator. `actions` maps method name -> the `Action` it represents.

    Only methods named as keys in `actions` are wrapped; every other method on
    the class is left exactly as defined — no verification, no change in
    behavior. This matches a documented trade-off in the reference
    implementation Custos is modeled on (ARCHITECTURE1.md §18.3, Trap 2): if you
    need every method gated, name every method.
    """
    def decorator(cls: type) -> type:
        for method_name, action in actions.items():
            original = getattr(cls, method_name, None)
            if original is None:
                raise AttributeError(f"{cls.__name__} has no method {method_name!r} to protect")
            setattr(cls, method_name, protect(
                original, action=action, target=target, tier=tier, on_violation=on_violation,
                passport=passport, revocation_store=revocation_store, trust_engine=trust_engine,
                claim_resolver=claim_resolver, observation_resolver=observation_resolver,
            ))
        return cls
    return decorator


shield_class = shield


def protect_agent(
    instance: Any,
    *,
    actions: dict[str, Action],
    passport: AgentPassport,
    target: str = "",
    tier: VerificationTier | None = None,
    on_violation: str = "raise",
    revocation_store: RevocationStore | None = None,
    trust_engine: TrustEngine | None = None,
    claim_resolver: ClaimResolver | None = None,
    observation_resolver: ObservationResolver | None = None,
) -> Any:
    """Wrap a live instance in place and return it. Only the named methods are
    protected — see `shield`'s docstring for why unlisted methods are left
    untouched. Only the specific names in `actions` are ever `getattr`'d, never a
    blind `dir(instance)` enumeration, so no unrelated `@property` is evaluated
    as a side effect."""
    for method_name, action in actions.items():
        original = getattr(instance, method_name, None)
        if original is None:
            raise AttributeError(f"{instance!r} has no method {method_name!r} to protect")
        setattr(instance, method_name, protect(
            original, action=action, target=target, tier=tier, on_violation=on_violation,
            passport=passport, revocation_store=revocation_store, trust_engine=trust_engine,
            claim_resolver=claim_resolver, observation_resolver=observation_resolver,
        ))
    return instance


shield_object = protect_agent
