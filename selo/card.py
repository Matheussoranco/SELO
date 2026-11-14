"""Agent Card A2A 1.0 com a extensao SELO (especificacao, secao 7).

O Card e assinado com JWS EdDSA destacada sobre o JCS do Card sem o campo `signatures`,
como no A2A. Os dados do SELO ficam em `capabilities.extensions[].params`.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import EXTENSION_URI, PROTOCOL, jcs
from .crypto.primitives import b64u, ed25519_verify, unb64u
from .errors import SeloError
from .identity import Identity, KelState, verify_kel

SUITE = "x25519-sha256-chachapoly"
CLOCK_SKEW = 120
DEFAULT_VALIDITY = 24 * 3600
MAX_LIFETIME = 7 * 24 * 3600
DEFAULT_MAX_CARD_AGE = 24 * 3600
WELL_KNOWN = "/.well-known/agent-card.json"
ENDPOINTS = {"envelope": "/selo/v1/envelope", "session": "/selo/v1/session", "push": "/selo/v1/push"}


def normalize_base(url: str) -> str:
    return url.rstrip("/")


def _signing_input(protected: str, card: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in card.items() if k != "signatures"}
    return (protected + "." + b64u(jcs.canonicalize(body))).encode("ascii")


def build_card(identity: Identity, base_url: str, *, name: str, description: str = "",
               skills: Optional[List[Dict[str, Any]]] = None,
               attestations: Optional[List[Dict[str, Any]]] = None,
               iat: int, validity: int = DEFAULT_VALIDITY, version: str = "1.0.0") -> Dict[str, Any]:
    if not 0 < validity <= MAX_LIFETIME:
        raise SeloError("bad_validity")
    base = normalize_base(base_url)
    params = {
        "v": PROTOCOL, "suite": SUITE, "agent_id": identity.agent_id, "kel": identity.kel,
        "iat": int(iat), "exp": int(iat) + validity, "attestations": list(attestations or []),
        "endpoints": dict(ENDPOINTS),
    }
    card: Dict[str, Any] = {
        "name": name,
        "description": description or f"Agente SELO {name}",
        "version": version,
        "supportedInterfaces": [{"url": base, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
        "capabilities": {
            "streaming": True,
            "pushNotifications": True,
            "extensions": [{"uri": EXTENSION_URI, "required": True,
                            "description": "SELO: A2A cifrado de ponta a ponta. Requisicoes em claro sao recusadas.",
                            "params": params}],
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": skills or [{"id": "default", "name": name, "description": description or name,
                              "tags": ["selo"]}],
    }
    header = {"alg": "EdDSA", "kid": f"{identity.agent_id}#{identity.seq}", "typ": "JOSE"}
    protected = b64u(jcs.canonicalize(header))
    sig = identity.sig_key.sign(_signing_input(protected, card))
    card["signatures"] = [{"protected": protected, "signature": b64u(sig)}]
    return card


@dataclass
class CardInfo:
    agent_id: str
    kel: KelState
    kel_raw: List[Dict[str, Any]]
    base_url: str
    iat: int
    exp: int
    attestations: List[Dict[str, Any]]
    card: Dict[str, Any] = field(repr=False)

    @property
    def agree_pub(self) -> bytes:
        return self.kel.current.agree_pub

    def pin(self) -> tuple:
        return (len(self.kel_raw) - 1, self.kel.head)


def selo_params(card: Any) -> Dict[str, Any]:
    try:
        exts = card["capabilities"]["extensions"]
    except (TypeError, KeyError):
        raise SeloError("not_selo", "Card sem extensoes") from None
    for ext in exts if isinstance(exts, list) else []:
        if isinstance(ext, dict) and ext.get("uri") == EXTENSION_URI:
            params = ext.get("params")
            if isinstance(params, dict):
                return params
    raise SeloError("not_selo", "Card sem a extensao SELO")


def verify_card(card: Any, *, now: float, max_card_age: int = DEFAULT_MAX_CARD_AGE,
                expected_id: Optional[str] = None) -> CardInfo:
    if not isinstance(card, dict):
        raise SeloError("bad_card")
    p = selo_params(card)
    if p.get("v") != PROTOCOL:
        raise SeloError("bad_card", "versao do protocolo")
    if p.get("suite") != SUITE:
        raise SeloError("unsupported_suite", str(p.get("suite")))
    kel_raw = p.get("kel")
    st = verify_kel(kel_raw)
    if st.revoked:
        raise SeloError("identity_revoked", st.agent_id)
    if p.get("agent_id") != st.agent_id:
        raise SeloError("bad_card", "agent_id nao deriva da KEL")
    if expected_id is not None and st.agent_id != expected_id:
        raise SeloError("identity_mismatch", "Card de outro agente")
    iat, exp = p.get("iat"), p.get("exp")
    if type(iat) is not int or type(exp) is not int:
        raise SeloError("bad_card", "iat/exp")
    if not (iat <= now + CLOCK_SKEW and now < exp and exp - iat <= MAX_LIFETIME
            and now - iat <= max_card_age):
        raise SeloError("card_stale", f"iat={iat} exp={exp} now={int(now)}")
    sigs = card.get("signatures")
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
        raise SeloError("bad_signature", "Card sem assinatura unica")
    sig = sigs[0]
    try:
        header = jcs_load(unb64u(sig["protected"]))
    except (KeyError, ValueError, TypeError):
        raise SeloError("bad_signature", "cabecalho JWS") from None
    if header != {"alg": "EdDSA", "kid": f"{st.agent_id}#{st.seq}", "typ": "JOSE"}:
        raise SeloError("bad_signature", "cabecalho JWS inesperado")
    if not ed25519_verify(st.current.sig_pub, unb64u(sig.get("signature", "")),
                          _signing_input(sig["protected"], card)):
        raise SeloError("bad_signature", "assinatura do Card")
    try:
        base = normalize_base(card["supportedInterfaces"][0]["url"])
    except (KeyError, IndexError, TypeError):
        raise SeloError("bad_card", "supportedInterfaces") from None
    atts = p.get("attestations", [])
    if not isinstance(atts, list):
        raise SeloError("bad_card", "attestations")
    return CardInfo(st.agent_id, st, kel_raw, base, iat, exp, atts, card)


def jcs_load(raw: bytes) -> Any:
    import json
    return json.loads(raw.decode("utf-8"))


def local_view(card: Dict[str, Any], local_url: str) -> Dict[str, Any]:
    """Copia do Card de um par, verificada pelo sidecar, com a URL trocada pelo proxy local.

    A assinatura original deixa de valer depois da troca, entao e removida; o sidecar marca
    `params.verified_by_sidecar`."""
    view = copy.deepcopy(card)
    view["supportedInterfaces"] = [{"url": local_url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    view.pop("signatures", None)
    selo_params(view)["verified_by_sidecar"] = True
    return view
