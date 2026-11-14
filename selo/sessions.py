"""Sessoes Noise IK + Double Ratchet (especificacao, secao 9). Implementacao no ticket #12;
por enquanto todo envio usa o envelope de um tiro."""

from __future__ import annotations

from typing import Any, Dict, Iterator

from .errors import SeloError
from .net import Request, Response


class SessionManager:
    def __init__(self, sidecar: Any) -> None:
        self.sc = sidecar

    def call(self, info: Any, trust: Any, rpc: Dict[str, Any]) -> Dict[str, Any]:
        return self.sc.call_envelope(info, trust, rpc)

    def stream(
        self, info: Any, trust: Any, rpc: Dict[str, Any]
    ) -> Iterator[Dict[str, Any]]:
        raise SeloError("session_required", "streaming exige sessao")

    def handle_handshake(self, req: Request) -> Response:
        raise SeloError("unknown_session")

    def handle_message(self, req: Request, sid: str) -> Response:
        raise SeloError("unknown_session")
