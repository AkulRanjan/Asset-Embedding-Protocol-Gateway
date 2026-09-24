from __future__ import annotations

from oracle.cache import TTLCache


def test_set_then_get_returns_the_value():
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    cache.set("3M", "value")
    assert cache.get("3M") == "value"


def test_missing_key_returns_none():
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    assert cache.get("missing") is None


def test_expired_entry_returns_none_and_is_evicted(monkeypatch):
    cache: TTLCache[str] = TTLCache(ttl_seconds=10)
    clock = [1000.0]
    monkeypatch.setattr("oracle.cache.time.monotonic", lambda: clock[0])

    cache.set("3M", "value")
    clock[0] += 11  # just past the 10s TTL
    assert cache.get("3M") is None
    # Evicted, not merely reported stale — the internal dict no longer carries it.
    assert "3M" not in cache._values


def test_entry_at_exactly_the_ttl_boundary_is_still_expired(monkeypatch):
    """`>` in the implementation means the boundary sample itself is expired, not fresh."""
    cache: TTLCache[str] = TTLCache(ttl_seconds=10)
    clock = [1000.0]
    monkeypatch.setattr("oracle.cache.time.monotonic", lambda: clock[0])

    cache.set("3M", "value")
    clock[0] += 10
    assert cache.get("3M") == "value"
    clock[0] += 0.001
    assert cache.get("3M") is None


def test_set_overwrites_an_existing_key():
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    cache.set("3M", "first")
    cache.set("3M", "second")
    assert cache.get("3M") == "second"


def test_cache_is_monotonic_clock_based_not_wall_clock(monkeypatch):
    """A wall-clock jump (e.g. NTP correction) must not affect freshness."""
    cache: TTLCache[str] = TTLCache(ttl_seconds=10)
    clock = [500.0]
    monkeypatch.setattr("oracle.cache.time.monotonic", lambda: clock[0])
    cache.set("3M", "value")
    clock[0] += 5
    assert cache.get("3M") == "value"


def test_keys_are_independent():
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    cache.set("3M", "a")
    cache.set("6M", "b")
    assert cache.get("3M") == "a"
    assert cache.get("6M") == "b"
