"""Primitivas compartilhadas: X25519, HKDF (extract/expand separados), HMAC, AEAD, hash, b64u."""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..errors import SeloError

RAW = serialization.Encoding.Raw
RAW_PUB = serialization.PublicFormat.Raw
RAW_PRIV = serialization.PrivateFormat.Raw
NOENC = serialization.NoEncryption()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str):
        raise SeloError("bad_encoding", "esperado texto base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise SeloError("bad_encoding", "base64url invalido") from None


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt or b"\x00" * 32, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# -- X25519 -------------------------------------------------------------------------------
def x25519_generate() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def x25519_from_bytes(sk: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(sk)


def x25519_pub(sk: x25519.X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(RAW, RAW_PUB)


def x25519_priv(sk: x25519.X25519PrivateKey) -> bytes:
    return sk.private_bytes(RAW, RAW_PRIV, NOENC)


def x25519_dh(sk: x25519.X25519PrivateKey, pk: bytes) -> bytes:
    if len(pk) != 32:
        raise SeloError("bad_key", "chave X25519 deve ter 32 bytes")
    try:
        out = sk.exchange(x25519.X25519PublicKey.from_public_bytes(pk))
    except ValueError:
        raise SeloError("bad_key", "ponto de baixa ordem") from None
    if out == b"\x00" * 32:
        raise SeloError("bad_key", "segredo DH nulo")
    return out


# -- Ed25519 ------------------------------------------------------------------------------
def ed25519_generate() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def ed25519_from_bytes(sk: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(sk)


def ed25519_pub(sk: ed25519.Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(RAW, RAW_PUB)


def ed25519_priv(sk: ed25519.Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(RAW, RAW_PRIV, NOENC)


def ed25519_verify(pub: bytes, sig: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


# -- AEAD ---------------------------------------------------------------------------------
def aead_seal(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise SeloError("bad_ciphertext") from None


def ct_eq(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)
