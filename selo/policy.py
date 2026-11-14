"""Gancho de politica (especificacao, secao 15). Implementacao completa no ticket #10."""

from __future__ import annotations

from typing import Any, Optional


class NullHook:
    def check(self, direction: str, stage: str, peer_id: str, peer_org: Optional[str], rpc: Any,
              method: Optional[str] = None) -> None:
        return None


def load_hook(spec: Optional[str]) -> NullHook:
    if spec:
        raise NotImplementedError("gancho de politica: ticket #10")
    return NullHook()
