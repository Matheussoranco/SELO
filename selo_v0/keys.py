"""Hierarquia de chaves do SELO e documentos assinados.

Semente mestra M (so da organizacao)
   |  K_{a,0} = HKDF(M, salt = H(org), info = "selo/seed" || a)
   v
Semente do agente a na epoca e:   K_{a,e+1} = Expand(K_{a,e}, "selo/ratchet")     (sentido unico)
Chave de acordo (X25519):         s_{a,e}   = Expand(K_{a,e}, "selo/agree");  P_{a,e} = s_{a,e} * G

O agente guarda apenas K_{a,e} (apaga as epocas antigas: sigilo progressivo por epoca).
A organizacao recalcula qualquer s_{a,e} a partir de M: o "escrow" e estrutural,
nao um segundo encapsulamento que o remetente poderia omitir ou falsificar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from .util import SeloError, b64d, b64e, canon, hkdf, hkdf_expand, lp, sha256

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def pub_raw(key) -> bytes:
    return key.public_bytes(**RAW)


# --------------------------------------------------------------------------- derivacao
def seed_epoch0(master: bytes, org_name: str, agent_id: str) -> bytes:
    return hkdf(master, b"selo/seed/v1" + lp(agent_id.encode()), salt=sha256(org_name.encode()))


def ratchet(seed: bytes) -> bytes:
    return hkdf_expand(seed, b"selo/ratchet/v1")


def seed_at(master: bytes, org_name: str, agent_id: str, epoch: int) -> bytes:
    """K_{a,e}: a organizacao percorre a cadeia desde a epoca 0 (O(e) hashes)."""
    if epoch < 0:
        raise SeloError("bad_epoch")
    seed = seed_epoch0(master, org_name, agent_id)
    for _ in range(epoch):
        seed = ratchet(seed)
    return seed


def agree_private(seed: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(hkdf_expand(seed, b"selo/agree/v1"))


def agree_public_raw(seed: bytes) -> bytes:
    return pub_raw(agree_private(seed).public_key())


@dataclass
class EpochKeys:
    """Estado do agente: guarda so as sementes das epocas e-1 e e (apaga as anteriores)."""

    epoch: int
    seeds: Dict[int, bytes] = field(default_factory=dict)

    @classmethod
    def start(cls, epoch: int, seed: bytes) -> "EpochKeys":
        return cls(epoch, {epoch: seed})

    def advance_to(self, epoch: int) -> None:
        if epoch < self.epoch:
            raise SeloError("clock_went_back")
        latest = max(self.seeds)
        seed = self.seeds[latest]
        while latest < epoch:
            seed = ratchet(seed)
            latest += 1
            self.seeds[latest] = seed
        self.epoch = epoch
        self.seeds = {e: s for e, s in self.seeds.items() if e >= epoch - 1}

    def agree_key(self, epoch: int) -> x25519.X25519PrivateKey:
        """Chave da epoca pedida: e-1 (tolerancia), e, ou e+1 (relogio do remetente adiantado)."""
        if epoch in self.seeds and epoch >= self.epoch - 1:
            return agree_private(self.seeds[epoch])
        if epoch == self.epoch + 1:
            return agree_private(ratchet(self.seeds[self.epoch]))
        raise SeloError("epoch_out_of_range")


# --------------------------------------------------------------------------- documentos assinados
def sign_doc(sk: ed25519.Ed25519PrivateKey, domain: str, body: Dict[str, Any]) -> Dict[str, Any]:
    return {"b": body, "sig": b64e(sk.sign(domain.encode() + b"\x00" + canon(body)))}


def verify_doc(pk_raw: bytes, domain: str, doc: Any) -> Dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != {"b", "sig"} or not isinstance(doc["b"], dict):
        raise SeloError("bad_document")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk_raw).verify(
            b64d(doc["sig"]), domain.encode() + b"\x00" + canon(doc["b"]))
    except InvalidSignature:
        raise SeloError("bad_signature") from None
    return doc["b"]


def load_ed25519_public(raw_b64: Any) -> ed25519.Ed25519PublicKey:
    raw = b64d(raw_b64)
    if len(raw) != 32:
        raise SeloError("bad_key")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class OrgParams:
    """Parametros publicos da organizacao (ancora de confianca de todos os agentes)."""

    name: str
    sig_pub: bytes            # Ed25519 bruta (32 bytes)
    genesis: int              # instante da epoca 0
    epoch_seconds: int

    def epoch_of(self, t: float) -> int:
        return max(0, (int(t) - self.genesis) // self.epoch_seconds)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "sig_pub": b64e(self.sig_pub),
                "genesis": self.genesis, "epoch_seconds": self.epoch_seconds}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "OrgParams":
        return OrgParams(d["name"], b64d(d["sig_pub"]), int(d["genesis"]), int(d["epoch_seconds"]))


def verify_cert(org: OrgParams, cert: Any, at: Optional[float] = None,
                revoked: Optional[set] = None) -> Dict[str, Any]:
    """Valida certificado de identidade (assinado pela organizacao, validade, revogacao)."""
    body = verify_doc(org.sig_pub, "selo/cert", cert)
    if body.get("t") != "cert" or body.get("org") != org.name:
        raise SeloError("bad_cert")
    if at is not None and not body["nbf"] <= at <= body["naf"]:
        raise SeloError("cert_expired")
    if revoked and body.get("serial") in revoked:
        raise SeloError("cert_revoked")
    return body


def verify_epoch_entry(org: OrgParams, entry: Any, at: float) -> Dict[str, Any]:
    body = verify_doc(org.sig_pub, "selo/epoch", entry)
    if body.get("t") != "epoch" or body.get("org") != org.name:
        raise SeloError("bad_entry")
    if not body["nbf"] <= at <= body["naf"]:
        raise SeloError("entry_expired")
    if len(b64d(body["agree_pub"])) != 32:
        raise SeloError("bad_key")
    return body
