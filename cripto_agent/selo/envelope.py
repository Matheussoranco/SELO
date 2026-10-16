"""Envelope SELO: cifragem hibrida (estilo HPKE) para a chave de acordo da epoca do destinatario,
mais assinatura Ed25519 do remetente sobre o transcript e o texto cifrado.

  Z   = X25519(e, P_{R,epoch})                         (e = chave efemera do remetente)
  th  = SHA256("selo/th" || canon(header) || P_{R,epoch})
  key || nonce = HKDF(Z, salt = th, info = "selo/aead")   (32 + 12 bytes)
  ct  = ChaCha20-Poly1305(key, nonce, canon(body), aad = canon(header))
  sig = Ed25519(sk_S, "selo/env" || th || SHA256(ct))

Nao existe segundo encapsulamento para a organizacao: ela le a mensagem recalculando
s_{R,epoch} a partir da semente mestra (ver keys.py).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .keys import OrgParams, load_ed25519_public, pub_raw, verify_cert
from .util import SeloError, b64d, b64e, canon, check_id, hkdf, sha256

VERSION = "selo/1"
MAX_ENVELOPE = 256 * 1024
MAX_BODY = 128 * 1024
CLOCK_SKEW = 120          # tolerancia de relogio (s)
MAX_TTL = 120             # validade maxima de uma mensagem (s)
DEFAULT_TTL = 60

HEADER_FIELDS = {"v", "org", "sender", "recipient", "epoch", "msg", "iat", "exp", "eph"}
ENVELOPE_FIELDS = {"h", "cert", "ct", "sig"}


@dataclass(frozen=True)
class Opened:
    header: Dict[str, Any]
    body: Dict[str, Any]
    sender_cert: Dict[str, Any]
    digest: str            # SHA256 do envelope inteiro (para trilha de auditoria)


def _transcript(header: Dict[str, Any], recipient_pub: bytes) -> bytes:
    return sha256(b"selo/th\x00", canon(header), recipient_pub)


def _aead_material(shared: bytes, th: bytes) -> tuple[bytes, bytes]:
    okm = hkdf(shared, b"selo/aead/v1", salt=th, length=44)
    return okm[:32], okm[32:]


def _dh(private: x25519.X25519PrivateKey, public: x25519.X25519PublicKey) -> bytes:
    try:
        return private.exchange(public)
    except ValueError:
        raise SeloError("bad_key", "ponto de baixa ordem") from None


def seal(*, org: OrgParams, sender_id: str, sender_sk: ed25519.Ed25519PrivateKey,
         sender_cert: Dict[str, Any], recipient_id: str, recipient_epoch: int,
         recipient_agree_pub: bytes, body: Dict[str, Any], now: int,
         ttl: int = DEFAULT_TTL) -> Dict[str, Any]:
    if not 0 < ttl <= MAX_TTL:
        raise SeloError("bad_ttl")
    body = dict(body, sender=sender_id, recipient=recipient_id)
    plaintext = canon(body)
    if len(plaintext) > MAX_BODY:
        raise SeloError("body_too_large")
    eph = x25519.X25519PrivateKey.generate()
    header = {
        "v": VERSION, "org": org.name, "sender": sender_id, "recipient": recipient_id,
        "epoch": recipient_epoch, "msg": b64e(os.urandom(16)), "iat": now, "exp": now + ttl,
        "eph": b64e(pub_raw(eph.public_key())),
    }
    th = _transcript(header, recipient_agree_pub)
    shared = _dh(eph, x25519.X25519PublicKey.from_public_bytes(recipient_agree_pub))
    key, nonce = _aead_material(shared, th)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, canon(header))
    sig = sender_sk.sign(b"selo/env\x00" + th + sha256(ct))
    return {"h": header, "cert": sender_cert, "ct": b64e(ct), "sig": b64e(sig)}


def peek_header(envelope: Any) -> Dict[str, Any]:
    """Valida a forma do envelope e devolve o cabecalho (ainda nao confiavel)."""
    if (not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS
            or not isinstance(envelope["h"], dict) or set(envelope["h"]) != HEADER_FIELDS):
        raise SeloError("invalid_envelope")
    h = envelope["h"]
    if (h["v"] != VERSION or not isinstance(h["epoch"], int) or isinstance(h["epoch"], bool)
            or not all(type(h[k]) is int for k in ("iat", "exp"))):
        raise SeloError("invalid_envelope")
    check_id(h["sender"]), check_id(h["recipient"])
    for k in ("msg", "eph"):
        if not isinstance(h[k], str):
            raise SeloError("invalid_envelope")
    return h


def open_envelope(envelope: Any, *, org: OrgParams, agree_sk: x25519.X25519PrivateKey,
                  my_id: Optional[str], now: Optional[float], revoked: Optional[set] = None
                  ) -> Opened:
    """Autentica e decifra. `now=None` desliga as janelas de tempo (leitura de auditoria)."""
    h = peek_header(envelope)
    if h["org"] != org.name:
        raise SeloError("org_mismatch")
    if my_id is not None and h["recipient"] != my_id:
        raise SeloError("wrong_recipient")
    if now is not None:
        if (not now - CLOCK_SKEW <= h["iat"] <= now + CLOCK_SKEW
                or not now < h["exp"] <= h["iat"] + MAX_TTL):
            raise SeloError("invalid_lifetime")
    cert = verify_cert(org, envelope["cert"], at=h["iat"] if now is None else now, revoked=revoked)
    if cert["id"] != h["sender"] or "agent" not in cert["roles"]:
        raise SeloError("identity_mismatch")

    ct = b64d(envelope["ct"])
    if len(ct) > MAX_ENVELOPE:
        raise SeloError("body_too_large")
    th = _transcript(h, pub_raw(agree_sk.public_key()))
    try:
        load_ed25519_public(cert["sig_pub"]).verify(
            b64d(envelope["sig"]), b"selo/env\x00" + th + sha256(ct))
    except InvalidSignature:
        raise SeloError("bad_signature") from None

    eph = b64d(h["eph"])
    if len(eph) != 32:
        raise SeloError("bad_key")
    shared = _dh(agree_sk, x25519.X25519PublicKey.from_public_bytes(eph))
    key, nonce = _aead_material(shared, th)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ct, canon(h))
    except InvalidTag:
        raise SeloError("bad_ciphertext") from None

    try:
        body = json.loads(plaintext)
    except ValueError:
        raise SeloError("invalid_payload") from None
    if (not isinstance(body, dict) or body.get("sender") != h["sender"]
            or body.get("recipient") != h["recipient"]):
        raise SeloError("identity_mismatch")
    return Opened(h, body, cert, sha256(canon(envelope)).hex())
