"""Double Ratchet (Signal, rev. 4) com X25519, HKDF-SHA256, HMAC-SHA256 e ChaCha20-Poly1305.

Parametros (especificacao, secao 9.3):

* KDF_RK(rk, dh) = HKDF-SHA256(salt=rk, ikm=dh, info="selo/1/rk", L=64) -> (rk, ck)
* KDF_CK(ck)     = (HMAC(ck, 0x02), HMAC(ck, 0x01))                      -> (ck, mk)
* chave/nonce da mensagem = HKDF-SHA256(salt=0^32, ikm=mk, info="selo/1/mk", L=44)
* MAX_SKIP = 256 por cadeia; no maximo MAX_STORED chaves puladas guardadas.

O envio e dividido em `next_send()` (avanca a cadeia e devolve cabecalho e chave) e
`seal_with()`, porque o dado associado (AD) inclui o cabecalho e a capsula de escrow, que
depende da chave da mensagem. A decifragem e transacional: se falhar, o estado nao muda.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from ..errors import SeloError
from .primitives import (
    aead_open,
    aead_seal,
    b64u,
    hkdf,
    hmac_sha256,
    unb64u,
    x25519_dh,
    x25519_from_bytes,
    x25519_generate,
    x25519_priv,
    x25519_pub,
)

MAX_SKIP = 256
MAX_STORED = 1024
ROOT_INFO = b"selo/1/ratchet-root"


def root_from_handshake(ck: bytes, h: bytes) -> bytes:
    """SK inicial do ratchet a partir do estado final do Noise (especificacao, 9.2)."""
    return hkdf(ck, salt=h, info=ROOT_INFO, length=32)


def kdf_rk(rk: bytes, dh: bytes) -> Tuple[bytes, bytes]:
    out = hkdf(dh, salt=rk, info=b"selo/1/rk", length=64)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    return hmac_sha256(ck, b"\x02"), hmac_sha256(ck, b"\x01")


def message_key_material(mk: bytes) -> Tuple[bytes, bytes]:
    out = hkdf(mk, salt=b"\x00" * 32, info=b"selo/1/mk", length=44)
    return out[:32], out[32:]


def seal_with(mk: bytes, ad: bytes, pt: bytes) -> bytes:
    key, nonce = message_key_material(mk)
    return aead_seal(key, nonce, ad, pt)


def open_with(mk: bytes, ad: bytes, ct: bytes) -> bytes:
    key, nonce = message_key_material(mk)
    return aead_open(key, nonce, ad, ct)


class Ratchet:
    def __init__(self) -> None:
        self.dhs: Optional[x25519.X25519PrivateKey] = None
        self.dhr: Optional[bytes] = None
        self.rk = b""
        self.cks: Optional[bytes] = None
        self.ckr: Optional[bytes] = None
        self.ns = self.nr = self.pn = 0
        self.skipped: Dict[Tuple[bytes, int], bytes] = {}

    # -- inicializacao --------------------------------------------------------------------
    @classmethod
    def init_alice(
        cls, sk: bytes, bob_pub: bytes, dhs: Optional[x25519.X25519PrivateKey] = None
    ) -> "Ratchet":
        r = cls()
        r.dhs = dhs or x25519_generate()
        r.dhr = bob_pub
        r.rk, r.cks = kdf_rk(sk, x25519_dh(r.dhs, bob_pub))
        return r

    @classmethod
    def init_bob(cls, sk: bytes, bob_keypair: x25519.X25519PrivateKey) -> "Ratchet":
        r = cls()
        r.dhs = bob_keypair
        r.rk = sk
        return r

    # -- envio ----------------------------------------------------------------------------
    def can_send(self) -> bool:
        return self.cks is not None

    def next_send(self) -> Tuple[Dict[str, Any], bytes]:
        if self.cks is None:
            raise SeloError(
                "ratchet_not_ready", "o respondedor so envia depois de receber"
            )
        self.cks, mk = kdf_ck(self.cks)
        hdr = {"dh": b64u(x25519_pub(self.dhs)), "pn": self.pn, "n": self.ns}
        self.ns += 1
        return hdr, mk

    # -- recebimento ----------------------------------------------------------------------
    def receive_key(self, hdr: Dict[str, Any]) -> bytes:
        """Avanca o estado e devolve a chave da mensagem com cabecalho `hdr`.

        Use `decrypt` (transacional) em vez deste metodo quando houver texto cifrado."""
        dh, pn, n = _parse_hdr(hdr)
        key = (dh, n)
        if key in self.skipped:
            return self.skipped.pop(key)
        if dh != self.dhr:
            self._skip(pn)
            self._dh_ratchet(dh)
        self._skip(n)
        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1
        return mk

    def decrypt(self, hdr: Dict[str, Any], ad: bytes, ct: bytes) -> Tuple[bytes, bytes]:
        """Decifra; devolve (texto claro, chave da mensagem). Nada muda se falhar."""
        snapshot = self._snapshot()
        try:
            mk = self.receive_key(hdr)
            return open_with(mk, ad, ct), mk
        except SeloError:
            self._restore(snapshot)
            raise
        except Exception:
            self._restore(snapshot)
            raise SeloError("bad_ciphertext") from None

    def _skip(self, until: int) -> None:
        if self.ckr is None:
            return
        if until - self.nr > MAX_SKIP:
            raise SeloError("ratchet_skip", "mensagens puladas demais")
        while self.nr < until:
            self.ckr, mk = kdf_ck(self.ckr)
            self.skipped[(self.dhr, self.nr)] = mk
            self.nr += 1
        while len(self.skipped) > MAX_STORED:
            self.skipped.pop(next(iter(self.skipped)))

    def _dh_ratchet(self, dh: bytes) -> None:
        self.pn, self.ns, self.nr = self.ns, 0, 0
        self.dhr = dh
        self.rk, self.ckr = kdf_rk(self.rk, x25519_dh(self.dhs, self.dhr))
        self.dhs = x25519_generate()
        self.rk, self.cks = kdf_rk(self.rk, x25519_dh(self.dhs, self.dhr))

    # -- persistencia ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        def opt(b: Optional[bytes]) -> Optional[str]:
            return None if b is None else b64u(b)

        return {
            "dhs": b64u(x25519_priv(self.dhs)),
            "dhr": opt(self.dhr),
            "rk": b64u(self.rk),
            "cks": opt(self.cks),
            "ckr": opt(self.ckr),
            "ns": self.ns,
            "nr": self.nr,
            "pn": self.pn,
            "skipped": [[b64u(d), n, b64u(mk)] for (d, n), mk in self.skipped.items()],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Ratchet":
        def opt(s: Optional[str]) -> Optional[bytes]:
            return None if s is None else unb64u(s)

        r = cls()
        r.dhs = x25519_from_bytes(unb64u(d["dhs"]))
        r.dhr, r.rk, r.cks, r.ckr = (
            opt(d["dhr"]),
            unb64u(d["rk"]),
            opt(d["cks"]),
            opt(d["ckr"]),
        )
        r.ns, r.nr, r.pn = d["ns"], d["nr"], d["pn"]
        r.skipped = {(unb64u(a), n): unb64u(c) for a, n, c in d["skipped"]}
        return r

    def _snapshot(self) -> Dict[str, Any]:
        return {
            "dhs": self.dhs,
            "dhr": self.dhr,
            "rk": self.rk,
            "cks": self.cks,
            "ckr": self.ckr,
            "ns": self.ns,
            "nr": self.nr,
            "pn": self.pn,
            "skipped": copy.copy(self.skipped),
        }

    def _restore(self, s: Dict[str, Any]) -> None:
        for k, v in s.items():
            setattr(self, k, v)


def _parse_hdr(hdr: Any) -> Tuple[bytes, int, int]:
    if not isinstance(hdr, dict) or set(hdr) != {"dh", "pn", "n"}:
        raise SeloError("bad_header")
    pn, n = hdr["pn"], hdr["n"]
    if not all(type(x) is int and 0 <= x < 2**32 for x in (pn, n)):
        raise SeloError("bad_header")
    dh = unb64u(hdr["dh"])
    if len(dh) != 32:
        raise SeloError("bad_header")
    return dh, pn, n
