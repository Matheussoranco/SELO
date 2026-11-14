"""Erros do SELO. Cada erro tem um codigo estavel, que e o que trafega na rede."""

from __future__ import annotations

from typing import Any, Dict, Optional

#: Codigos JSON-RPC usados pelo SELO (faixa reservada a implementacoes: -32000 a -32099).
JSONRPC_CODES = {
    "extension_required": -32090,
    "unknown_session": -32091,
    "session_expired": -32092,
    "policy_denied": -32093,
    "peer_untrusted": -32094,
    "push_destination_denied": -32095,
    "bad_request": -32600,
}


class SeloError(Exception):
    """Falha de protocolo com codigo estavel (`code`) e detalhe opcional para logs."""

    def __init__(self, code: str, detail: str = "", data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.data = data or {}

    def jsonrpc_error(self) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": JSONRPC_CODES.get(self.code, -32000), "message": self.code}
        data = dict(self.data)
        if self.detail:
            data.setdefault("detail", self.detail)
        if data:
            err["data"] = data
        return err
