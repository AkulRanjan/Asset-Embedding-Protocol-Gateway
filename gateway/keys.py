"""Agent public-key resolution. Mutable process state, so it lives outside the protocol package."""

from __future__ import annotations

import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custos_protocol.crypto import b64_to_public_key


class AgentAlreadyRegistered(ValueError):
    """Raised when a caller attempts to replace an established key binding."""


class AgentKeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._lock = threading.Lock()

    def register(self, agent_id: str, public_key_b64: str) -> None:
        key = b64_to_public_key(public_key_b64)
        with self._lock:
            if agent_id in self._keys:
                raise AgentAlreadyRegistered(agent_id)
            self._keys[agent_id] = key

    def get(self, agent_id: str) -> Ed25519PublicKey | None:
        with self._lock:
            return self._keys.get(agent_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)
