"""One-liner observability API: log everything, block nothing.

`observe.py` deliberately does not import `verification.py` — enforced by
`tests/test_architecture.py` — so observability is structurally incapable of
blocking a call, not just incapable by convention. Two invariants hold for every
decorated call, both tested explicitly: the wrapped function always executes,
and a raised exception always propagates (never swallowed).

The identity object `passport()` returns here is the same `AgentPassport` shape
`shield.py` consumes, which is what makes moving from `@observe` to `@protect`
a one-line diff rather than a rewrite.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from custos_protocol.passport import AgentPassport

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

_MAX_EVENTS = 10_000


def _safe_repr(value: Any) -> Any:
    """JSON-serializable or a repr() fallback — never raises on export."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)


@dataclass
class ObservationEvent:
    agent_id: str
    agent_name: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    success: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0
    caller: str | None = None
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": self.action,
            "parameters": {key: _safe_repr(value) for key, value in self.parameters.items()},
            "result": _safe_repr(self.result),
            "error": self.error,
            "success": self.success,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "caller": self.caller,
        }


class ObservationStore:
    """Thread-safe ring buffer. Callbacks fire outside the lock, and an
    exception in one is caught and logged — a misbehaving dashboard hook can't
    deadlock or crash the observed agent."""

    def __init__(self, maxlen: int = _MAX_EVENTS) -> None:
        self._events: deque[ObservationEvent] = deque(maxlen=maxlen)
        self._stats: dict[str, dict[str, int]] = {}
        self._callbacks: list[Callable[[ObservationEvent], None]] = []
        self._lock = threading.Lock()

    def record(self, event: ObservationEvent) -> None:
        with self._lock:
            self._events.append(event)
            counters = self._stats.setdefault(event.agent_id, {"total": 0, "success": 0, "errors": 0})
            counters["total"] += 1
            counters["success" if event.success else "errors"] += 1
            callbacks = list(self._callbacks)

        for callback in callbacks:
            try:
                callback(event)
            except Exception:
                logger.exception("Observation callback raised; ignoring")

    def on_event(self, callback: Callable[[ObservationEvent], None]) -> None:
        with self._lock:
            self._callbacks.append(callback)

    @property
    def events(self) -> list[ObservationEvent]:
        with self._lock:
            return list(self._events)

    def events_for_agent(self, agent_id: str) -> list[ObservationEvent]:
        with self._lock:
            return [event for event in self._events if event.agent_id == agent_id]

    def stats(self, agent_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if agent_id is not None:
                return dict(self._stats.get(agent_id, {"total": 0, "success": 0, "errors": 0}))
            return {agent: dict(counters) for agent, counters in self._stats.items()}

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._stats.clear()

    def export_json(self) -> str:
        return json.dumps([event.to_dict() for event in self.events], indent=2)


_default_store = ObservationStore()
_default_store_lock = threading.Lock()


def get_observation_store() -> ObservationStore:
    with _default_store_lock:
        return _default_store


def set_observation_store(store: ObservationStore) -> None:
    global _default_store
    with _default_store_lock:
        _default_store = store


def passport(name: str, domain: str = "localhost", **kwargs: Any) -> AgentPassport:
    """Shorthand for a quick identity. Accepts the same boundary kwargs as
    `AgentPassport.create` (`allowed_actions`, `denied_actions`,
    `monetary_limit_per_txn`, ...). The returned object is a real passport —
    the same one `shield.protect()` can later consume unchanged."""
    return AgentPassport.create(domain=domain, agent_name=name, **kwargs)


def _is_property(owner: Any, name: str) -> bool:
    """`inspect.getattr_static` never triggers a descriptor's `__get__`, unlike
    plain `getattr` — this is what lets class/instance wrapping skip properties
    without evaluating them as a side effect."""
    try:
        return isinstance(inspect.getattr_static(owner, name), property)
    except AttributeError:
        return False


def _build_parameters(func: Callable, args: tuple, kwargs: dict, log_params: bool) -> dict[str, Any]:
    if not log_params:
        return {}
    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        parameters = dict(bound.arguments)
    except TypeError:
        parameters = dict(kwargs)
    parameters.pop("self", None)
    return parameters


def _caller_location() -> str | None:
    frame = inspect.currentframe()
    try:
        # Two frames up: this helper's own frame, then the wrapper that called it.
        caller_frame = frame.f_back.f_back if frame and frame.f_back else None
        if caller_frame is None:
            return None
        return f"{caller_frame.f_code.co_filename}:{caller_frame.f_lineno}"
    finally:
        del frame


def _make_wrapper(
    func: Callable,
    *,
    agent: AgentPassport,
    action: str,
    store: ObservationStore,
    log_params: bool,
    log_result: bool,
) -> Callable:
    def _record(args: tuple, kwargs: dict, *, started: float, result: Any, error: BaseException | None) -> None:
        latency_ms = (time.perf_counter() - started) * 1000
        event = ObservationEvent(
            agent_id=agent.agent.id, agent_name=agent.agent.id.rsplit(":", 1)[-1],
            action=action, parameters=_build_parameters(func, args, kwargs, log_params),
            result=result if (log_result and error is None) else None,
            error=repr(error) if error is not None else None,
            success=error is None, latency_ms=latency_ms, caller=_caller_location(),
        )
        store.record(event)
        logger.debug("observed %s success=%s latency_ms=%.3f", action, error is None, latency_ms)

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
            except BaseException as exc:
                _record(args, kwargs, started=started, result=None, error=exc)
                raise
            _record(args, kwargs, started=started, result=result, error=None)
            return result
        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except BaseException as exc:
            _record(args, kwargs, started=started, result=None, error=exc)
            raise
        _record(args, kwargs, started=started, result=result, error=None)
        return result
    return sync_wrapper


def observe(
    target: F | AgentPassport | None = None,
    *,
    action: str | None = None,
    store: ObservationStore | None = None,
    log_params: bool = False,
    log_result: bool = False,
) -> Any:
    """Three forms: `@observe` (bare), `@observe()` (auto-creates a passport
    named after the function), `@observe(existing_passport)`.

    `log_params=False` by default — arguments are not captured unless you opt
    in. This is a deliberate divergence from the reference implementation
    Custos is modeled on, which defaults to capturing every argument (including
    any secrets or PII a caller passes) with no redaction.
    """
    store = store or get_observation_store()

    def decorator(func: F) -> F:
        agent = target if isinstance(target, AgentPassport) else passport(func.__name__)
        return _make_wrapper(  # type: ignore[return-value]
            func, agent=agent, action=action or func.__name__,
            store=store, log_params=log_params, log_result=log_result,
        )

    if target is None or isinstance(target, AgentPassport):
        return decorator
    # Bare @observe with no parentheses: target is the function itself.
    return decorator(target)


def observe_class(
    *,
    passport_obj: AgentPassport | None = None,
    store: ObservationStore | None = None,
    log_params: bool = False,
    log_result: bool = False,
) -> Callable[[type], type]:
    """Class decorator: wraps every public, non-property callable at
    decoration time. Operates on the class object itself, so `getattr` on a
    `property` returns the descriptor, never triggers it — no evaluation
    side effect."""
    def decorator(cls: type) -> type:
        agent = passport_obj or passport(cls.__name__)
        for name in dir(cls):
            if name.startswith("_") or _is_property(cls, name):
                continue
            attr = getattr(cls, name)
            if not inspect.isfunction(attr):
                continue
            setattr(cls, name, _make_wrapper(
                attr, agent=agent, action=name, store=store or get_observation_store(),
                log_params=log_params, log_result=log_result,
            ))
        return cls
    return decorator


def observe_agent(
    instance: Any,
    *,
    passport_obj: AgentPassport | None = None,
    store: ObservationStore | None = None,
    log_params: bool = False,
    log_result: bool = False,
) -> Any:
    """Wrap every public, non-property callable on a live instance in place.
    `inspect.getattr_static` is used to detect properties before any
    `getattr` that could trigger one, so decorating an already-constructed
    object never evaluates its properties as a side effect."""
    agent = passport_obj or passport(type(instance).__name__)
    for name in dir(instance):
        if name.startswith("_") or _is_property(instance, name):
            continue
        attr = inspect.getattr_static(instance, name, None)
        if not (inspect.isfunction(attr) or inspect.ismethod(attr)):
            continue
        bound = getattr(instance, name)
        setattr(instance, name, _make_wrapper(
            bound, agent=agent, action=name, store=store or get_observation_store(),
            log_params=log_params, log_result=log_result,
        ))
    return instance
