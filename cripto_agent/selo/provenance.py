"""Proveniencia e contaminacao (taint): controle de fluxo de integridade para agentes LLM.

Cada conteudo que entra no contexto de um agente carrega um *carimbo* (stamp) assinado por
sua origem, com o hash do conteudo e um conjunto de marcas de contaminacao T (ex.: WEB, EMAIL).
A contaminacao de uma requisicao e a UNIAO das marcas dos carimbos citados (um semirreticulado
(P(T), subconjunto, uniao)); cada capacidade declara um conjunto proibido F e a requisicao so
e aceita se T ∩ F = ∅. A contaminacao so desce por *endosso* assinado por um humano.

Hipotese explicita: o *harness* (codigo deterministico ao redor do LLM) cita todos os carimbos
do contexto. O LLM nao e confiavel; a omissao pelo harness e detectavel por auditoria
(a organizacao decifra tudo) -- ver audit.py.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric import ed25519

from .keys import OrgParams, sign_doc, verify_cert, verify_doc
from .util import SeloError, b64d, b64e, content_hash

MAX_STAMPS = 256
UNKNOWN = "UNKNOWN_SOURCE"          # marca imposta a origens sem manifesto conhecido
KINDS = {"user", "result"}


def make_stamp(*, origin_id: str, sk: ed25519.Ed25519PrivateKey, cert: Dict[str, Any],
               content: Any, taint: Iterable[str], ts: int, kind: str,
               cap: str = "", manifest: str = "") -> Dict[str, Any]:
    body = {"h": content_hash(content), "taint": sorted(set(taint)), "origin": origin_id,
            "ts": ts, "kind": kind, "cap": cap, "m": manifest}
    doc = sign_doc(sk, "selo/stamp", body)
    doc["cert"] = cert
    return doc


def verify_stamp(org: OrgParams, doc: Any, revoked: Optional[set] = None) -> Dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != {"b", "sig", "cert"}:
        raise SeloError("bad_stamp")
    b = doc["b"]
    if (not isinstance(b, dict) or set(b) != {"h", "taint", "origin", "ts", "kind", "cap", "m"}
            or b["kind"] not in KINDS or type(b["ts"]) is not int
            or not all(isinstance(b[k], str) for k in ("h", "origin", "cap", "m"))):
        raise SeloError("bad_stamp")
    cert = verify_cert(org, doc["cert"], at=b["ts"], revoked=revoked)   # valido NO instante do carimbo
    if cert["id"] != b.get("origin"):
        raise SeloError("bad_stamp", "origem")
    role = "user" if b["kind"] == "user" else "agent"
    if role not in cert["roles"]:
        raise SeloError("bad_stamp", "papel")
    verify_doc(b64d(cert["sig_pub"]), "selo/stamp", {"b": b, "sig": doc["sig"]})
    if (not isinstance(b.get("taint"), list) or not all(isinstance(t, str) for t in b["taint"])):
        raise SeloError("bad_stamp", "taint")
    return b


def make_endorsement(*, user_id: str, sk: ed25519.Ed25519PrivateKey, cert: Dict[str, Any],
                     content_hash_hex: str, remove: Iterable[str], ts: int, sid: str,
                     cap: str = "", ttl: int = 3600) -> Dict[str, Any]:
    """Endosso com escopo minimo: este item, esta sessao, esta capacidade, por tempo limitado."""
    body = {"h": content_hash_hex, "remove": sorted(set(remove)), "by": user_id,
            "ts": ts, "exp": ts + ttl, "sid": sid, "cap": cap}
    doc = sign_doc(sk, "selo/endorse", body)
    doc["cert"] = cert
    return doc


def verify_endorsement(org: OrgParams, doc: Any, now: float, sid: str, cap: str,
                       revoked: Optional[set] = None) -> Optional[Dict[str, Any]]:
    """Endosso autentico e aplicavel -> corpo; autentico mas fora de escopo/validade -> None
    (ignorado: uma sessao carrega endossos de varias capacidades); forjado/sem papel -> erro."""
    if not isinstance(doc, dict) or set(doc) != {"b", "sig", "cert"}:
        raise SeloError("bad_endorsement")
    cert = verify_cert(org, doc["cert"], at=now, revoked=revoked)
    b = doc["b"]
    if not isinstance(b, dict) or cert["id"] != b.get("by") or "endorser" not in cert["roles"]:
        raise SeloError("bad_endorsement", "papel")
    verify_doc(b64d(cert["sig_pub"]), "selo/endorse", {"b": b, "sig": doc["sig"]})
    if (type(b.get("ts")) is not int or type(b.get("exp")) is not int
            or not isinstance(b.get("remove"), list)):
        raise SeloError("bad_endorsement", "forma")
    if not b["ts"] <= now < b["exp"] or b.get("sid") != sid or b.get("cap") not in ("", cap):
        return None
    return b


def effective_taint(org: OrgParams, stamps: List[Any], endorsements: List[Any], now: float,
                    manifests: Callable[[str], Optional[Dict[str, Any]]],
                    revoked: Optional[set] = None, *, sid: str = "", cap: str = "") -> Set[str]:
    """Contaminacao da requisicao: ∪ sobre carimbos de (marcas do carimbo ∪ marcas do manifesto
    - marcas removidas por endosso valido).  Carimbo invalido = requisicao rejeitada."""
    if len(stamps) > MAX_STAMPS or len(endorsements) > MAX_STAMPS:
        raise SeloError("too_many_stamps")
    valid_end = [b for b in (verify_endorsement(org, e, now, sid, cap, revoked) for e in endorsements)
                 if b is not None]
    total: Set[str] = set()
    for doc in stamps:
        b = verify_stamp(org, doc, revoked)
        tags = set(b["taint"])
        if b["kind"] == "result":
            m = manifests(b["m"])
            if m is None or m["name"] != b["cap"]:
                tags.add(UNKNOWN)
            else:
                tags |= set(m["taint_out"])
        for e in valid_end:
            if e["h"] == b["h"]:
                tags -= set(e["remove"])
        total |= tags
    return total


def _leaves(value: Any) -> List[str]:
    """Folhas relevantes de um argumento: strings (>= 3 caracteres) e numeros, em minusculas."""
    out: List[str] = []
    if isinstance(value, bool) or value is None:
        return out
    if isinstance(value, str):
        if len(value.strip()) >= 3:
            out.append(value.strip().lower())
    elif isinstance(value, (int, float)):
        out.append(str(value).lower())
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_leaves(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            out.extend(_leaves(v))
    return out


def _contains(text: str, leaf: str) -> bool:
    if leaf.replace(".", "", 1).replace("-", "", 1).isdigit():
        return re.search(r"(?<![\w.])" + re.escape(leaf) + r"(?![\w])", text) is not None
    return leaf in text


@dataclass
class Session:
    """Contexto de um agente (lado do harness): lista monotona de carimbos observados.

    O harness guarda tambem o TEXTO de cada item (nunca enviado) para o modo `args`, em que cada
    chamada cita apenas os carimbos dos itens de onde vieram seus argumentos."""

    sid: str = field(default_factory=lambda: b64e(os.urandom(9)))
    stamps: List[Dict[str, Any]] = field(default_factory=list)
    endorsements: List[Dict[str, Any]] = field(default_factory=list)
    texts: Dict[str, str] = field(default_factory=dict)         # hash do conteudo -> texto local

    def observe(self, stamp: Dict[str, Any], content: Any = None) -> None:
        self.stamps.append(stamp)
        if content is not None:
            self.texts[stamp["b"]["h"]] = (content if isinstance(content, str)
                                           else json.dumps(content, ensure_ascii=False)).lower()

    def cite_for(self, args: Dict[str, Any], only: Any = None) -> List[Dict[str, Any]]:
        """Carimbos a citar para uma chamada com estes argumentos (modo `args`).

        Cada folha do argumento e atribuida a itens do contexto por casamento textual. Folha
        presente em instrucao do usuario e confiavel. Folha sem origem conhecida (ex.: o modelo
        a inventou ou a transformou) faz o harness citar TODO o contexto (conservador)."""
        if only is not None:
            args = {k: v for k, v in args.items() if k in set(only)}
        user = [s for s in self.stamps if s["b"]["kind"] == "user"]
        user_text = " ".join(self.texts.get(s["b"]["h"], "") for s in user)
        cited = {id(s): s for s in user}
        for leaf in _leaves(args):
            if _contains(user_text, leaf):
                continue
            hit = [s for s in self.stamps if s["b"]["kind"] != "user"
                   and _contains(self.texts.get(s["b"]["h"], ""), leaf)]
            if not hit:
                return list(self.stamps)
            cited.update({id(s): s for s in hit})
        return [s for s in self.stamps if id(s) in cited]

    def endorse(self, endorsement: Dict[str, Any]) -> None:
        self.endorsements.append(endorsement)


@dataclass
class Principal:
    """Pessoa (ou servico humano) com chave propria: carimba instrucoes e emite endossos."""

    id: str
    sk: ed25519.Ed25519PrivateKey
    cert: Dict[str, Any]
    clock: Callable[[], float]

    @classmethod
    def enroll(cls, org: Any, principal_id: str, roles: Iterable[str],
               clock: Callable[[], float]) -> "Principal":
        from .keys import pub_raw
        sk = ed25519.Ed25519PrivateKey.generate()
        return cls(principal_id, sk, org.enroll(principal_id, pub_raw(sk.public_key()), list(roles)), clock)

    def instruct(self, text: str) -> Dict[str, Any]:
        """Carimbo de uma instrucao humana: contaminacao vazia (conteudo confiavel)."""
        return make_stamp(origin_id=self.id, sk=self.sk, cert=self.cert, content=text, taint=(),
                          ts=int(self.clock()), kind="user")

    def endorse(self, stamp: Dict[str, Any], remove: Iterable[str], session: "Session",
                cap: str = "", ttl: int = 3600) -> Dict[str, Any]:
        return make_endorsement(user_id=self.id, sk=self.sk, cert=self.cert,
                                content_hash_hex=stamp["b"]["h"], remove=remove,
                                ts=int(self.clock()), sid=session.sid, cap=cap, ttl=ttl)
