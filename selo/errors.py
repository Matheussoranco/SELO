"""Erros do SELO. Cada erro tem um codigo estavel, que e o que trafega na rede."""

from __future__ import annotations

from typing import Any, Dict, Optional

#: Codigos JSON-RPC usados pelo SELO (faixa reservada a implementacoes: -32000 a -32099).
#: Codigos padrao JSON-RPC 2.0: -32700 a -32600.
JSONRPC_CODES = {
    # Padroes JSON-RPC
    "parse_error": -32700,
    "invalid_request": -32600,
    "method_not_found": -32601,
    "invalid_params": -32602,
    "internal_error": -32603,
    # SELO especificos (faixa -32090 a -32060)
    "extension_required": -32090,
    "unknown_session": -32091,
    "session_expired": -32092,
    "policy_denied": -32093,
    "peer_untrusted": -32094,
    "push_destination_denied": -32095,
    "card_stale": -32096,
    "kel_fork": -32097,
    "identity_revoked": -32098,
    "peer_revoked": -32099,
    "bad_attestation": -32080,
    "bad_org_doc": -32081,
    "revocations_stale": -32082,
    "bad_signature": -32083,
    "bad_ciphertext": -32084,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
    "bad_signature": -32083,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
    "bad_signature": -32083,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
    "bad_signature": -32083,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
    "bad_signature": -32083,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
    "bad_signature": -32083,
    "replay": -32085,
    "invalid_lifetime": -32086,
    "wrong_recipient": -32087,
    "escrow_required": -32088,
    "handshake_failed": -32089,
    "bad_handshake": -32079,
    "ratchet_skip": -32078,
    "ratchet_not_ready": -32077,
    "bad_envelope": -32076,
    "bad_ttl": -32075,
    "body_too_large": -32074,
    "identity_mismatch": -32073,
    "bad_payload": -32072,
    "peer_error": -32071,
    "bad_response": -32070,
    "bad_request": -32600,
    "card_unavailable": -32069,
    "unsupported_suite": -32068,
    "bad_card": -32067,
}

# Deduplicar mantendo o primeiro valor (ja ha duplicatas acima)
_SEEN = set()
JSONRPC_CODES = {k: v for k, v in JSONRPC_CODES.items() if not (k in _SEEN or _SEEN.add(k))}


class SeloError(Exception):
    """Falha de protocolo com codigo estavel (`code`) e detalhe opcional para logs."""

    def __init__(
        self, code: str, detail: str = "", data: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.data = data or {}

    def jsonrpc_error(self) -> Dict[str, Any]:
        err: Dict[str, Any] = {
            "code": JSONRPC_CODES.get(self.code, -32000),
            "message": self.code,
        }
        data = dict(self.data)
        if self.detail:
            data.setdefault("detail", self.detail)
        if data:
            err["data"] = data
        return err