"""Regra de escolha do canal (especificacao, secao 9.6)."""

from __future__ import annotations

STREAMING_METHODS = frozenset({"SendStreamingMessage", "SubscribeToTask"})

ENVELOPE = "envelope"
SESSION = "session"


def is_streaming(method: str) -> bool:
    return method in STREAMING_METHODS


def choose(method: str, has_session: bool) -> str:
    """Canal para uma requisicao: streaming exige sessao; o resto usa a sessao se existir."""
    if is_streaming(method) or has_session:
        return SESSION
    return ENVELOPE


def fallback_after_lost_session(method: str) -> str:
    """Canal do reenvio depois de `unknown_session` (secao 9.5)."""
    return SESSION if is_streaming(method) else ENVELOPE
