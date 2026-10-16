"""Autoridade da organizacao: PKI, hierarquia de chaves, admissao de manifestos e leitura auditada.

A organizacao e a unica a conhecer a semente mestra M. Ela (1) emite certificados de identidade
(Ed25519, gerados pelo proprio agente: a organizacao NAO conhece a chave de assinatura, logo
pode LER mas nao FORJAR mensagens), (2) entrega a cada agente a semente da epoca corrente,
(3) publica chaves publicas de acordo por epoca (documentos assinados de curta duracao: a
revogacao ocorre por nao renovacao), (4) admite manifestos no log Merkle e (5) le mensagens
quando necessario, registrando cada leitura em um log de auditoria encadeado por hash.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from .envelope import Opened, open_envelope, peek_header
from .keys import (EpochKeys, OrgParams, agree_private, agree_public_raw, pub_raw, seed_at,
                   sign_doc)
from .manifest import MerkleLog, make_sth, manifest_hash, org_countersign, verify_manifest_doc
from .shamir import combine, random_secret, split
from .util import SeloError, b64e, canon, check_id, sha256

DAY = 86400
DEFAULT_CERT_TTL = 90 * DAY


class AuditLog:
    """Log append-only encadeado: h_i = SHA256(h_{i-1} || canon(registro_i))."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []

    def append(self, record: Dict[str, Any]) -> str:
        prev = self.records[-1]["h"] if self.records else "0" * 64
        record = dict(record, i=len(self.records), prev=prev)
        record["h"] = sha256(bytes.fromhex(prev), canon(record)).hex()
        self.records.append(record)
        return record["h"]

    def verify(self) -> bool:
        prev = "0" * 64
        for i, rec in enumerate(self.records):
            body = {k: v for k, v in rec.items() if k != "h"}
            if rec["i"] != i or rec["prev"] != prev:
                return False
            if sha256(bytes.fromhex(prev), canon(body)).hex() != rec["h"]:
                return False
            prev = rec["h"]
        return True


class Organization:
    def __init__(self, name: str, master: bytes, sig_sk: ed25519.Ed25519PrivateKey,
                 genesis: int, epoch_seconds: int = DAY,
                 clock: Callable[[], float] = time.time) -> None:
        check_id(name)
        self.name, self._master, self._sig_sk = name, master, sig_sk
        self.genesis, self.epoch_seconds, self.clock = genesis, epoch_seconds, clock
        self.params = OrgParams(name, pub_raw(sig_sk.public_key()), genesis, epoch_seconds)
        self.log = MerkleLog()
        self.docs: Dict[str, Dict[str, Any]] = {}      # hash do manifesto -> documento admitido
        self.index: Dict[str, int] = {}
        self.revoked: set = set()
        self.audit = AuditLog()
        self._serial = 0
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.urls: Dict[str, str] = {}

    @classmethod
    def create(cls, name: str, epoch_seconds: int = DAY, genesis: Optional[int] = None,
               clock: Callable[[], float] = time.time) -> "Organization":
        g = int(clock()) if genesis is None else genesis
        return cls(name, random_secret(), ed25519.Ed25519PrivateKey.generate(), g,
                   epoch_seconds, clock)

    # ----------------------------------------------------------------- custodia da semente M
    def master_shares(self, threshold: int, shares: int):
        return split(self._master, threshold, shares)

    @staticmethod
    def master_from_shares(parts) -> bytes:
        return combine(parts)

    # ----------------------------------------------------------------- identidades
    def now(self) -> int:
        return int(self.clock())

    def enroll(self, agent_id: str, sig_pub: bytes, roles: List[str],
               ttl: int = DEFAULT_CERT_TTL) -> Dict[str, Any]:
        """Emite o certificado. `sig_pub` e a chave publica que o AGENTE gerou."""
        check_id(agent_id)
        if not set(roles) <= {"agent", "user", "endorser", "publisher"} or not roles:
            raise SeloError("bad_roles")
        self._serial += 1
        t = self.now()
        body = {"t": "cert", "org": self.name, "id": agent_id, "sig_pub": b64e(sig_pub),
                "roles": sorted(set(roles)), "nbf": t, "naf": t + ttl, "serial": self._serial}
        self.agents[agent_id] = body
        return sign_doc(self._sig_sk, "selo/cert", body)

    def revoke(self, serial: int) -> None:
        self.revoked.add(serial)

    def revocation_list(self) -> Dict[str, Any]:
        return sign_doc(self._sig_sk, "selo/revoked",
                        {"serials": sorted(self.revoked), "ts": self.now()})

    def _check_epoch(self, epoch: int) -> int:
        """Limita o trabalho da cadeia de hashes: nunca alem da epoca atual + 1."""
        if type(epoch) is not int or not 0 <= epoch <= self.params.epoch_of(self.now()) + 1:
            raise SeloError("bad_epoch")
        return epoch

    def issue_seed(self, agent_id: str, epoch: Optional[int] = None) -> EpochKeys:
        """Entrega (canal autenticado de matricula) a semente da epoca atual para o agente."""
        e = self.params.epoch_of(self.now()) if epoch is None else self._check_epoch(epoch)
        return EpochKeys.start(e, seed_at(self._master, self.name, agent_id, e))

    def epoch_entry(self, agent_id: str, epoch: Optional[int] = None, url: str = "") -> Dict[str, Any]:
        url = url or self.urls.get(agent_id, "")
        """Chave publica de acordo do agente na epoca: documento curto assinado pela organizacao."""
        cert = self.agents.get(agent_id)
        if cert is None or cert["serial"] in self.revoked:
            raise SeloError("unknown_agent")
        cur = self.params.epoch_of(self.now())
        e = cur if epoch is None else self._check_epoch(epoch)
        if abs(e - cur) > 1:
            raise SeloError("bad_epoch")
        start = self.genesis + e * self.epoch_seconds
        body = {"t": "epoch", "org": self.name, "id": agent_id, "epoch": e,
                "agree_pub": b64e(agree_public_raw(seed_at(self._master, self.name, agent_id, e))),
                "url": url, "nbf": start - self.epoch_seconds // 2,
                "naf": start + self.epoch_seconds + self.epoch_seconds // 2}
        return sign_doc(self._sig_sk, "selo/epoch", body)

    # ----------------------------------------------------------------- manifestos
    def admit_manifest(self, publisher_doc: Dict[str, Any], approved: bool) -> Dict[str, Any]:
        """Admissao: a revisao (humana/automatica) acontece ANTES; aqui so se assina e registra."""
        if not approved:
            raise SeloError("manifest_rejected")
        probe = org_countersign(self._sig_sk, publisher_doc)
        verify_manifest_doc(self.params, probe, self.now(), self.revoked)
        h = manifest_hash(probe["m"])
        self.docs[h] = probe
        self.index[h] = self.log.append(probe)
        return probe

    def sth(self) -> Dict[str, Any]:
        return make_sth(self._sig_sk, self.log, self.now())

    def manifest_bundle(self, h: str):
        """(documento, prova de inclusao, STH) para o hash pedido, ou None."""
        if h not in self.docs:
            return None
        return self.docs[h], self.log.proof(self.index[h]), self.sth()

    # ----------------------------------------------------------------- leitura auditada
    def open(self, envelope: Dict[str, Any], auditor: str, reason: str) -> Opened:
        """Decifra qualquer mensagem recalculando s_{R,e}. Autentica o remetente (nao o forja)."""
        if not reason or not auditor:
            raise SeloError("audit_reason_required")
        h = peek_header(envelope)
        seed = seed_at(self._master, self.name, h["recipient"], self._check_epoch(h["epoch"]))
        opened = open_envelope(envelope, org=self.params, agree_sk=agree_private(seed),
                               my_id=None, now=None, revoked=self.revoked)
        self.audit.append({"ts": self.now(), "auditor": auditor, "reason": reason,
                           "envelope": opened.digest, "sender": h["sender"],
                           "recipient": h["recipient"]})
        return opened

    def export_public(self) -> str:
        return json.dumps(self.params.to_dict())
