"""Noise Protocol Framework (rev. 34), DH 25519, cifra ChaChaPoly, hash SHA256.

Implementa CipherState, SymmetricState e HandshakeState (secao 5) e os padroes N, NN, XX e IK
(secao 7). O SELO usa `Noise_IK_25519_ChaChaPoly_SHA256`; os outros padroes existem para
validar a maquina de estados contra mais vetores (tests/vectors/noise_cacophony_...json).
Sem PSK e sem rekey.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from ..errors import SeloError
from .primitives import (
    aead_open,
    aead_seal,
    hmac_sha256,
    sha256,
    x25519_dh,
    x25519_generate,
    x25519_pub,
)

HASHLEN = 32
DHLEN = 32
MAX_MESSAGE = 65535

PATTERNS = {
    # nome: (pre-mensagens do iniciador, pre-mensagens do respondedor, mensagens)
    "N": ([], ["s"], [["e", "es"]]),
    "NN": ([], [], [["e"], ["e", "ee"]]),
    "XX": ([], [], [["e"], ["e", "ee", "s", "es"], ["s", "se"]]),
    "IK": ([], ["s"], [["e", "es", "s", "ss"], ["e", "ee", "se"]]),
}
ONE_WAY = {"N"}


def noise_hkdf(ck: bytes, ikm: bytes, n: int) -> Tuple[bytes, ...]:
    temp = hmac_sha256(ck, ikm)
    out1 = hmac_sha256(temp, b"\x01")
    out2 = hmac_sha256(temp, out1 + b"\x02")
    if n == 2:
        return out1, out2
    return out1, out2, hmac_sha256(temp, out2 + b"\x03")


class CipherState:
    def __init__(self, k: Optional[bytes] = None) -> None:
        self.k, self.n = k, 0

    def has_key(self) -> bool:
        return self.k is not None

    def _nonce(self) -> bytes:
        if self.n >= 2**64 - 1:
            raise SeloError("noise_nonce_exhausted")
        return b"\x00" * 4 + self.n.to_bytes(8, "little")

    def encrypt_with_ad(self, ad: bytes, pt: bytes) -> bytes:
        if self.k is None:
            return pt
        ct = aead_seal(self.k, self._nonce(), ad, pt)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ct: bytes) -> bytes:
        if self.k is None:
            return ct
        pt = aead_open(self.k, self._nonce(), ad, ct)
        self.n += 1
        return pt


class SymmetricState:
    def __init__(self, protocol_name: bytes) -> None:
        self.h = (
            protocol_name.ljust(HASHLEN, b"\x00")
            if len(protocol_name) <= HASHLEN
            else sha256(protocol_name)
        )
        self.ck = self.h
        self.cs = CipherState()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, temp_k = noise_hkdf(self.ck, ikm, 2)
        self.cs = CipherState(temp_k[:32])

    def mix_hash(self, data: bytes) -> None:
        self.h = sha256(self.h, data)

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = self.cs.encrypt_with_ad(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = self.cs.decrypt_with_ad(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self) -> Tuple[CipherState, CipherState]:
        k1, k2 = noise_hkdf(self.ck, b"", 2)
        return CipherState(k1[:32]), CipherState(k2[:32])


class HandshakeState:
    """Maquina de estados do handshake. `e` pode ser fixado (vetores de teste)."""

    def __init__(
        self,
        pattern: str,
        initiator: bool,
        prologue: bytes = b"",
        s: Optional[x25519.X25519PrivateKey] = None,
        e: Optional[x25519.X25519PrivateKey] = None,
        rs: Optional[bytes] = None,
        re: Optional[bytes] = None,
    ) -> None:
        if pattern not in PATTERNS:
            raise SeloError("noise_pattern", pattern)
        self.pattern, self.initiator = pattern, initiator
        self.name = f"Noise_{pattern}_25519_ChaChaPoly_SHA256".encode()
        self.ss = SymmetricState(self.name)
        self.s, self.e, self.rs, self.re = s, e, rs, re
        self._preset_e = e
        self.ss.mix_hash(prologue)
        pre_i, pre_r, self.messages = PATTERNS[pattern]
        for owner_is_initiator, tokens in ((True, pre_i), (False, pre_r)):
            for t in tokens:
                local = owner_is_initiator == initiator
                if t == "s":
                    key = x25519_pub(self.s) if local else self.rs
                elif t == "e":
                    key = x25519_pub(self.e) if local else self.re
                else:
                    raise SeloError("noise_pattern", t)
                if key is None:
                    raise SeloError("noise_missing_key", f"pre-mensagem {t}")
                self.ss.mix_hash(key)
        self.idx = 0
        self.result: Optional[Tuple[CipherState, CipherState]] = None

    @property
    def h(self) -> bytes:
        return self.ss.h

    @property
    def ck(self) -> bytes:
        return self.ss.ck

    def my_turn(self) -> bool:
        return (self.idx % 2 == 0) == self.initiator

    def finished(self) -> bool:
        return self.idx >= len(self.messages)

    def _dh(self, token: str) -> bytes:
        if token == "ee":
            return x25519_dh(self.e, self.re)
        if token == "ss":
            return x25519_dh(self.s, self.rs)
        if token == "es":
            return (
                x25519_dh(self.e, self.rs)
                if self.initiator
                else x25519_dh(self.s, self.re)
            )
        if token == "se":
            return (
                x25519_dh(self.s, self.re)
                if self.initiator
                else x25519_dh(self.e, self.rs)
            )
        raise SeloError("noise_pattern", token)

    def _maybe_split(self) -> None:
        self.idx += 1
        if self.finished():
            self.result = self.ss.split()

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.finished() or not self.my_turn():
            raise SeloError("noise_state", "nao e a vez de escrever")
        out = bytearray()
        for t in self.messages[self.idx]:
            if t == "e":
                if self.e is None or self._preset_e is None:
                    self.e = x25519_generate()
                self._preset_e = None
                pub = x25519_pub(self.e)
                out += pub
                self.ss.mix_hash(pub)
            elif t == "s":
                out += self.ss.encrypt_and_hash(x25519_pub(self.s))
            else:
                self.ss.mix_key(self._dh(t))
        out += self.ss.encrypt_and_hash(payload)
        if len(out) > MAX_MESSAGE:
            raise SeloError("noise_too_large")
        self._maybe_split()
        return bytes(out)

    def read_message(self, message: bytes) -> bytes:
        if self.finished() or self.my_turn():
            raise SeloError("noise_state", "nao e a vez de ler")
        if len(message) > MAX_MESSAGE:
            raise SeloError("noise_too_large")
        pos = 0
        for t in self.messages[self.idx]:
            if t == "e":
                if len(message) < pos + DHLEN:
                    raise SeloError("noise_short")
                self.re = message[pos : pos + DHLEN]
                pos += DHLEN
                self.ss.mix_hash(self.re)
            elif t == "s":
                n = DHLEN + (16 if self.ss.cs.has_key() else 0)
                if len(message) < pos + n:
                    raise SeloError("noise_short")
                self.rs = self.ss.decrypt_and_hash(message[pos : pos + n])
                pos += n
            else:
                self.ss.mix_key(self._dh(t))
        payload = self.ss.decrypt_and_hash(message[pos:])
        self._maybe_split()
        return payload

    def transport(self) -> Tuple[CipherState, CipherState]:
        """(envio, recebimento) deste lado, apos o fim do handshake."""
        if self.result is None:
            raise SeloError("noise_state", "handshake incompleto")
        c1, c2 = self.result
        return (c1, c2) if self.initiator else (c2, c1)


def one_way(pattern: str) -> bool:
    return pattern in ONE_WAY


__all__: List[str] = [
    "HandshakeState",
    "CipherState",
    "SymmetricState",
    "noise_hkdf",
    "one_way",
]
