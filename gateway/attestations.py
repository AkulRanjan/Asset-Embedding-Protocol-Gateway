"""Admin-registered attestation data: known frameworks and known build/prompt
hashes. Mutable process state, so it lives outside the protocol package — same
rationale as AgentKeyRegistry."""

from __future__ import annotations

import threading


class AttestationRegistry:
    def __init__(self) -> None:
        self._frameworks: set[str] = set()
        self._build_hashes: dict[str, str] = {}
        self._prompt_hashes: dict[str, str] = {}
        self._lock = threading.Lock()

    def register_framework(self, framework_id: str) -> None:
        with self._lock:
            self._frameworks.add(framework_id)

    def register_build_hash(self, framework_id: str, build_hash: str) -> None:
        with self._lock:
            self._build_hashes[framework_id] = build_hash

    def register_prompt_hash(self, agent_id: str, system_prompt_hash: str) -> None:
        with self._lock:
            self._prompt_hashes[agent_id] = system_prompt_hash

    @property
    def frameworks(self) -> set[str]:
        with self._lock:
            return set(self._frameworks)

    @property
    def build_hashes(self) -> dict[str, str]:
        with self._lock:
            return dict(self._build_hashes)

    @property
    def prompt_hashes(self) -> dict[str, str]:
        with self._lock:
            return dict(self._prompt_hashes)
