"""HPKE (RFC 9180), modo base, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305.

Implementacao direta das secoes 4, 5 e 7 da RFC, sobre as primitivas da `cryptography`.
Validada pelos vetores oficiais em tests/vectors/hpke_base_x25519_sha256_chachapoly.json.
"""

from __future__ import annotations

from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from ..errors import SeloError
from .primitives import (aead_open, aead_seal, hkdf_expand, hkdf_extract, x25519_dh,
                         x25519_from_bytes, x25519_generate, x25519_pub)

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
N_SECRET = N_ENC = N_PK = N_SK = N_H = N_K = 32
N_N = 12
MODE_BASE = 0x00


def i2osp(n: int, w: int) -> bytes:
    return n.to_bytes(w, "big")


KEM_SUITE = b"KEM" + i2osp(KEM_ID, 2)
HPKE_SUITE = b"HPKE" + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


# -- KEM (secao 4.1) ----------------------------------------------------------------------
def derive_keypair(ikm: bytes) -> x25519.X25519PrivateKey:
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    return x25519_from_bytes(labeled_expand(KEM_SUITE, prk, b"sk", b"", N_SK))


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, prk, b"shared_secret", kem_context, N_SECRET)


def encap(pk_r: bytes, sk_e: Optional[x25519.X25519PrivateKey] = None) -> Tuple[bytes, bytes]:
    sk_e = sk_e or x25519_generate()
    enc = x25519_pub(sk_e)
    dh = x25519_dh(sk_e, pk_r)
    return _extract_and_expand(dh, enc + pk_r), enc


def decap(enc: bytes, sk_r: x25519.X25519PrivateKey) -> bytes:
    if len(enc) != N_ENC:
        raise SeloError("bad_key", "enc HPKE deve ter 32 bytes")
    dh = x25519_dh(sk_r, enc)
    return _extract_and_expand(dh, enc + x25519_pub(sk_r))


# -- Contexto (secao 5) -------------------------------------------------------------------
class Context:
    def __init__(self, key: bytes, base_nonce: bytes, exporter_secret: bytes) -> None:
        self.key, self.base_nonce, self.exporter_secret = key, base_nonce, exporter_secret
        self.seq = 0

    def _nonce(self) -> bytes:
        if self.seq >= (1 << (8 * N_N)) - 1:
            raise SeloError("hpke_overflow")
        seq = i2osp(self.seq, N_N)
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq))

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        ct = aead_seal(self.key, self._nonce(), aad, pt)
        self.seq += 1
        return ct

    def open(self, aad: bytes, ct: bytes) -> bytes:
        pt = aead_open(self.key, self._nonce(), aad, ct)
        self.seq += 1
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return labeled_expand(HPKE_SUITE, self.exporter_secret, b"sec", exporter_context, length)


def key_schedule(shared_secret: bytes, info: bytes) -> Context:
    psk, psk_id = b"", b""
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", psk_id)
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    ctx = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", psk)
    return Context(labeled_expand(HPKE_SUITE, secret, b"key", ctx, N_K),
                   labeled_expand(HPKE_SUITE, secret, b"base_nonce", ctx, N_N),
                   labeled_expand(HPKE_SUITE, secret, b"exp", ctx, N_H))


def setup_base_s(pk_r: bytes, info: bytes,
                 sk_e: Optional[x25519.X25519PrivateKey] = None) -> Tuple[bytes, Context]:
    shared, enc = encap(pk_r, sk_e)
    return enc, key_schedule(shared, info)


def setup_base_r(enc: bytes, sk_r: x25519.X25519PrivateKey, info: bytes) -> Context:
    return key_schedule(decap(enc, sk_r), info)


def seal_base(pk_r: bytes, info: bytes, aad: bytes, pt: bytes) -> Tuple[bytes, bytes]:
    """Single-shot (secao 6.1): devolve (enc, ct)."""
    enc, ctx = setup_base_s(pk_r, info)
    return enc, ctx.seal(aad, pt)


def open_base(enc: bytes, sk_r: x25519.X25519PrivateKey, info: bytes, aad: bytes, ct: bytes) -> bytes:
    return setup_base_r(enc, sk_r, info).open(aad, ct)
