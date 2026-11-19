"""Envelope de um tiro (especificacao, secao 8): HPKE para o destinatario + assinatura Ed25519.

(enc, ctx) = HPKE.SetupBaseS(agree_pub do destinatario, info="selo/1/envelope")
ct         = ctx.Seal(aad=JCS(h), pt=JCS(corpo))
sig        = Ed25519(remetente, "selo/1/envelope" 0x00 || SHA256(JCS(h)) || enc || SHA256(ct)
                                || SHA256(JCS(escrow) ou ""))
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from . import PROTOCOL, jcs
from .card import CLOCK_SKEW, CardInfo
from .crypto import hpke
from .crypto.primitives import b64u, ed25519_verify, sha256, unb64u
from .errors import SeloError
from .escrow import EscrowTarget, capsule_digest, check_capsule_shape, make_capsule
from .identity import Identity

INFO = b"selo/1/envelope"
SIG_DOMAIN = b"selo/1/envelope\x00"
MAX_BODY = 256 * 1024
DEFAULT_TTL = 60
MAX_TTL = 300
TYPES = ("req", "resp", "push")
BASE_FIELDS = {
    "v",
    "t",
    "sender",
    "sender_card",
    "sender_seq",
    "recipient",
    "recipient_seq",
    "msg",
    "iat",
    "exp",
}


@dataclass
class Opened:
    header: Dict[str, Any]
    body: Dict[str, Any]
    sender: CardInfo
    digest: str


def seal(
    *,
    sender: Identity,
    sender_card_url: str,
    recipient: CardInfo,
    body: Dict[str, Any],
    t: str,
    now: float,
    ttl: int = DEFAULT_TTL,
    re: Optional[str] = None,
    escrow: Optional[EscrowTarget] = None,
    _fixed: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Sela um envelope. `_fixed` ({"msg": bytes, "eph": X25519PrivateKey}) existe so para
    gerar vetores de teste deterministicos; nunca use em producao."""
    if t not in TYPES or (t == "resp") != (re is not None):
        raise SeloError("bad_envelope", "tipo/re")
    if not 0 < ttl <= MAX_TTL:
        raise SeloError("bad_ttl")
    plaintext = jcs.canonicalize(body)
    if len(plaintext) > MAX_BODY - 4096:
        raise SeloError("body_too_large")
    iat = int(now)
    h: Dict[str, Any] = {
        "v": PROTOCOL,
        "t": t,
        "sender": sender.agent_id,
        "sender_card": sender_card_url,
        "sender_seq": sender.seq,
        "recipient": recipient.agent_id,
        "recipient_seq": recipient.kel.seq,
        "msg": b64u(_fixed["msg"] if _fixed else os.urandom(16)),
        "iat": iat,
        "exp": iat + ttl,
    }
    if re is not None:
        h["re"] = re
    aad = jcs.canonicalize(h)
    enc, ctx = hpke.setup_base_s(
        recipient.agree_pub, INFO, _fixed["eph"] if _fixed else None
    )
    capsule = make_capsule(escrow, aad, ctx.key + ctx.base_nonce) if escrow else None
    ct = ctx.seal(aad, plaintext)
    sig = sender.sig_key.sign(
        SIG_DOMAIN + sha256(aad) + enc + sha256(ct) + capsule_digest(capsule)
    )
    env: Dict[str, Any] = {"h": h, "enc": b64u(enc), "ct": b64u(ct), "sig": b64u(sig)}
    if capsule is not None:
        env["escrow"] = capsule
    return env


def peek(env: Any) -> Dict[str, Any]:
    """Valida a forma e devolve o cabecalho, ainda NAO autenticado."""
    if not isinstance(env, dict) or not (
        {"h", "enc", "ct", "sig"} <= set(env) <= {"h", "enc", "ct", "sig", "escrow"}
    ):
        raise SeloError("bad_envelope", "forma")
    h = env["h"]
    if not isinstance(h, dict):
        raise SeloError("bad_envelope", "cabecalho")
    t = h.get("t")
    expected = BASE_FIELDS | ({"re"} if t == "resp" else set())
    if set(h) != expected or t not in TYPES or h["v"] != PROTOCOL:
        raise SeloError("bad_envelope", "campos do cabecalho")
    for k in ("sender_seq", "recipient_seq", "iat", "exp"):
        if type(h[k]) is not int:
            raise SeloError("bad_envelope", k)
    for k in ("sender", "sender_card", "recipient", "msg") + (
        ("re",) if t == "resp" else ()
    ):
        if not isinstance(h[k], str) or not h[k]:
            raise SeloError("bad_envelope", k)
    for k in ("enc", "ct", "sig"):
        if not isinstance(env[k], str):
            raise SeloError("bad_envelope", k)
    return h


def check_lifetime(h: Dict[str, Any], now: float) -> None:
    if not (
        abs(now - h["iat"]) <= CLOCK_SKEW
        and now < h["exp"]
        and 0 < h["exp"] - h["iat"] <= MAX_TTL
    ):
        raise SeloError(
            "invalid_lifetime", f"iat={h['iat']} exp={h['exp']} now={int(now)}"
        )


def open_envelope(
    env: Any,
    *,
    me: Identity,
    now: float,
    resolve_sender: Callable[[Dict[str, Any]], CardInfo],
    replay: Callable[[str, str, int], None],
    escrow_org: Callable[[CardInfo], Optional[str]] = lambda _c: None,
    expect_type: Optional[str] = None,
    get_cached_sender_key: Optional[Callable[[Dict[str, Any]], Optional[bytes]]] = None,
) -> Opened:
    """Verifica e decifra na ordem da especificacao (8.3). Qualquer falha levanta SeloError.

    `resolve_sender(h)` busca, verifica e aplica a politica de confianca ao Card do remetente.
    `replay(sender, msg, exp)` levanta `replay` se o par ja foi visto (e o registra).
    `get_cached_sender_key(h)` opcional: retorna a chave de assinatura do remetente a partir
    do cache local (sem busca de rede) para verificar a assinatura ANTES de buscar o Card.
    Se retorna None (ex.: TOFU), o comportamento atual e mantido: busca o Card primeiro.
    """
    h = peek(env)
    if expect_type is not None and h["t"] != expect_type:
        raise SeloError("bad_envelope", "tipo inesperado")
    if h["recipient"] != me.agent_id:
        raise SeloError("wrong_recipient")
    agree_sk = me.agree_key_for(h["recipient_seq"], now)
    check_lifetime(h, now)

    # Tenta verificar a assinatura com chave em cache ANTES de buscar o Card (secao 8.3, ordem 5 antes de 4 para agentes conhecidos)
    cached_sig_pub = None
    if get_cached_sender_key is not None:
        cached_sig_pub = get_cached_sender_key(h)

    if cached_sig_pub is not None:
        # Verifica a assinatura com a chave em cache ANTES de buscar o Card
        capsule = env.get("escrow")
        aad = jcs.canonicalize(h)
        enc, ct = unb64u(env["enc"]), unb64u(env["ct"])
        if len(ct) > MAX_BODY:
            raise SeloError("body_too_large")
        if not ed25519_verify(
            cached_sig_pub,
            unb64u(env["sig"]),
            SIG_DOMAIN + sha256(aad) + enc + sha256(ct) + capsule_digest(capsule),
        ):
            raise SeloError("bad_signature")

    sender = resolve_sender(h)
    if sender.agent_id != h["sender"]:
        raise SeloError("identity_mismatch")
    if not sender.kel.key_usable(h["sender_seq"], now, h["iat"]):
        raise SeloError("bad_signature", "chave do remetente fora da janela")

    # Se nao verificamos com chave em cache, verifica agora com a chave do Card resolvido
    if cached_sig_pub is None:
        capsule = env.get("escrow")
        aad = jcs.canonicalize(h)
        enc, ct = unb64u(env["enc"]), unb64u(env["ct"])
        if len(ct) > MAX_BODY:
            raise SeloError("body_too_large")
        if not ed25519_verify(
            sender.kel.entry(h["sender_seq"]).sig_pub,
            unb64u(env["sig"]),
            SIG_DOMAIN + sha256(aad) + enc + sha256(ct) + capsule_digest(capsule),
        ):
            raise SeloError("bad_signature")

    replay(h["sender"], h["msg"], h["exp"])
    org = escrow_org(sender)
    if org is not None:
        check_capsule_shape(capsule, org)
    elif capsule is not None:
        raise SeloError("bad_envelope", "capsula de escrow inesperada")
    pt = hpke.setup_base_r(enc, agree_sk, INFO).open(aad, ct)
    try:
        body = json.loads(pt)
    except ValueError:
        raise SeloError("bad_payload") from None
    if not isinstance(body, dict):
        raise SeloError("bad_payload")
    return Opened(h, body, sender, b64u(sha256(jcs.canonicalize(env))))
