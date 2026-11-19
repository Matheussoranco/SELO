"""Organizacoes: atestacao, revogacao, federacao e escrow (especificacao, secoes 6 e 11).

Duas metades:

* ``Organization`` (lado da organizacao, ferramenta do operador): semente mestra no cofre de
  chaves, ancora Ed25519 e chave de escrow X25519 derivadas dela, descritor, atestacoes,
  lista de revogacao, servidor das listas e auditoria de trafego capturado.
* ``OrgTrust`` (lado do sidecar): decide se um par tem atestacao de uma ancora confiavel,
  com lista de revogacao fresca (falha fechada), e se o escrow se aplica a conversa.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from . import jcs
from .card import CLOCK_SKEW, CardInfo
from .crypto.primitives import (
    aead_open,
    b64u,
    ed25519_from_bytes,
    ed25519_pub,
    ed25519_verify,
    hkdf,
    sha256,
    unb64u,
    x25519_from_bytes,
    x25519_pub,
)
from .crypto.ratchet import open_with
from .errors import SeloError
from .escrow import EscrowTarget, capsule_digest, open_capsule
from .net import HttpClient, HttpServer, Request, Response
from .shamir import combine, random_secret, split

REVOCATIONS_DEFAULT = 3600
REVOCATIONS_MAX = 24 * 3600
ATTESTATION_DEFAULT = 30 * 24 * 3600


# -- documentos assinados ---------------------------------------------------------------
def sign_doc(sk: Any, kind: str, body: Dict[str, Any]) -> Dict[str, Any]:
    if body.get("t") != kind:
        raise SeloError("bad_org_doc", "tipo")
    return {
        "body": body,
        "sig": b64u(
            sk.sign(f"selo/1/{kind}".encode() + b"\x00" + jcs.canonicalize(body))
        ),
    }


def verify_doc(anchor_pub: bytes, kind: str, doc: Any) -> Dict[str, Any]:
    if (
        not isinstance(doc, dict)
        or set(doc) != {"body", "sig"}
        or not isinstance(doc["body"], dict)
    ):
        raise SeloError("bad_org_doc", "forma")
    body = doc["body"]
    if body.get("t") != kind:
        raise SeloError("bad_org_doc", f"esperado {kind}")
    data = f"selo/1/{kind}".encode() + b"\x00" + jcs.canonicalize(body)
    if not ed25519_verify(anchor_pub, unb64u(doc["sig"]), data):
        raise SeloError("bad_org_doc", f"assinatura de {kind}")
    return body


# -- lado da organizacao ----------------------------------------------------------------
class Organization:
    def __init__(
        self,
        name: str,
        master: bytes,
        revocations_url: str = "",
        escrow_enabled: bool = False,
    ) -> None:
        self.name, self.master = name, master
        self.revocations_url, self.escrow_enabled = revocations_url, escrow_enabled
        self.anchor = ed25519_from_bytes(
            hkdf(master, salt=b"", info=b"selo/1/anchor-key", length=32)
        )
        self.escrow_sk = x25519_from_bytes(
            hkdf(master, salt=b"", info=b"selo/1/escrow-key", length=32)
        )
        self.revoked: List[str] = []
        self.seq = 0
        self.audit = AuditLog()

    @classmethod
    def create(
        cls, name: str, revocations_url: str = "", escrow_enabled: bool = False
    ) -> "Organization":
        return cls(name, random_secret(), revocations_url, escrow_enabled)

    @property
    def anchor_pub(self) -> bytes:
        return ed25519_pub(self.anchor)

    def anchor_entry(self) -> Dict[str, Any]:
        """O que outro operador coloca em `trust.orgs` para confiar nesta organizacao."""
        return {
            "name": self.name,
            "anchor_pub": b64u(self.anchor_pub),
            "revocations_url": self.revocations_url,
        }

    def descriptor(self, now: float) -> Dict[str, Any]:
        escrow: Dict[str, Any] = {"enabled": self.escrow_enabled}
        if self.escrow_enabled:
            escrow["agree_pub"] = b64u(x25519_pub(self.escrow_sk))
        return sign_doc(
            self.anchor,
            "org",
            {
                "t": "org",
                "name": self.name,
                "anchor_pub": b64u(self.anchor_pub),
                "revocations_url": self.revocations_url,
                "escrow": escrow,
                "iat": int(now),
            },
        )

    def attest(
        self,
        agent_id: str,
        now: float,
        roles: Optional[List[str]] = None,
        validity: int = ATTESTATION_DEFAULT,
    ) -> Dict[str, Any]:
        return sign_doc(
            self.anchor,
            "attestation",
            {
                "t": "attestation",
                "org": self.name,
                "agent_id": agent_id,
                "roles": list(roles or ["agent"]),
                "iat": int(now),
                "exp": int(now) + validity,
            },
        )

    def revoke(self, agent_id: str) -> None:
        if agent_id not in self.revoked:
            self.revoked.append(agent_id)
            self.seq += 1

    def revocation_list(
        self, now: float, ttl: int = REVOCATIONS_DEFAULT
    ) -> Dict[str, Any]:
        if not 0 < ttl <= REVOCATIONS_MAX:
            raise SeloError("bad_ttl")
        return sign_doc(
            self.anchor,
            "revocations",
            {
                "t": "revocations",
                "org": self.name,
                "seq": self.seq,
                "iat": int(now),
                "next_update": int(now) + ttl,
                "revoked": sorted(self.revoked),
            },
        )

    def master_shares(self, threshold: int, shares: int) -> List[Tuple[int, str]]:
        return [(x, b64u(y)) for x, y in split(self.master, threshold, shares)]

    @staticmethod
    def master_from_shares(parts: List[Tuple[int, str]]) -> bytes:
        return combine([(x, unb64u(y)) for x, y in parts])

    # -- auditoria (escrow) ---------------------------------------------------------------
    def open_captured(
        self, records: List[Dict[str, Any]], auditor: str, reason: str
    ) -> List[Dict[str, Any]]:
        """Decifra mensagens capturadas que tem capsula de escrow desta organizacao.

        Cada leitura exige auditor e motivo e entra no log encadeado por hash."""
        if not auditor.strip() or not reason.strip():
            raise SeloError("audit_reason", "auditor e motivo sao obrigatorios")
        out = []
        for rec in records:
            msg = rec.get("data") if isinstance(rec, dict) and "data" in rec else rec
            if not isinstance(msg, dict) or not isinstance(msg.get("escrow"), dict):
                continue
            if msg["escrow"].get("org") != self.name:
                continue
            plaintext = self._open_one(msg)
            if plaintext is None:
                continue
            digest = b64u(sha256(jcs.canonicalize(msg)))
            self.audit.append(
                {
                    "auditor": auditor,
                    "reason": reason,
                    "digest": digest,
                    "t": int(time.time()),
                }
            )
            out.append({"digest": digest, "plaintext": plaintext})
        return out

    def _open_one(self, msg: Dict[str, Any]) -> Optional[Any]:
        cap = msg["escrow"]
        if "h" in msg:  # envelope
            aad = jcs.canonicalize(msg["h"])
            material = open_capsule(cap, self.escrow_sk, aad)
            key, nonce = material[:32], material[32:44]
            return json.loads(aead_open(key, nonce, aad, unb64u(msg["ct"])))
        if (
            "sid" in msg
        ):  # mensagem de sessao: o sentido nao vai na mensagem; tenta os dois
            for direction in ("i2r", "r2i"):
                base = jcs.canonicalize(
                    {"sid": msg["sid"], "dir": direction}
                ) + jcs.canonicalize(msg["hdr"])
                try:
                    mk = open_capsule(cap, self.escrow_sk, base)
                    return json.loads(
                        open_with(mk, base + capsule_digest(cap), unb64u(msg["ct"]))
                    )
                except SeloError:
                    continue
        return None

    # -- persistencia (estado da organizacao; a semente fica no cofre) --------------------
    def save_state(self, directory: str) -> None:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "org.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "name": self.name,
                    "revocations_url": self.revocations_url,
                    "escrow_enabled": self.escrow_enabled,
                    "revoked": self.revoked,
                    "seq": self.seq,
                },
                fh,
                indent=2,
            )
        self.audit.save(os.path.join(directory, "audit.jsonl"))

    @classmethod
    def load(cls, directory: str, keystore: Any) -> "Organization":
        with open(os.path.join(directory, "org.json"), encoding="utf-8") as fh:
            st = json.load(fh)
        master = keystore.load("org_master")
        if master is None:
            raise SeloError(
                "keystore_error", "semente mestra da organizacao ausente do cofre"
            )
        org = cls(st["name"], master, st["revocations_url"], st["escrow_enabled"])
        org.revoked, org.seq = st["revoked"], st["seq"]
        org.audit = AuditLog.load(os.path.join(directory, "audit.jsonl"))
        return org

    def serve(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        ssl_context: Any = None,
        clock: Any = time.time,
        ttl: int = REVOCATIONS_DEFAULT,
        reload_from: Optional[str] = None,
    ) -> HttpServer:
        """Serve /revocations e /descriptor. Com `reload_from`, rele o estado (revogacoes
        feitas pela CLI) a cada requisicao."""

        def handle(req: Request) -> Response:
            if reload_from:
                with open(
                    os.path.join(reload_from, "org.json"), encoding="utf-8"
                ) as fh:
                    st = json.load(fh)
                self.revoked, self.seq = st["revoked"], st["seq"]
            if req.method == "GET" and req.path == "/revocations":
                return Response(200, self.revocation_list(clock(), ttl))
            if req.method == "GET" and req.path == "/descriptor":
                return Response(200, self.descriptor(clock()))
            return Response(404, {"error": "not_found"})

        return HttpServer(host, port, handle, ssl_context).start()


class AuditLog:
    """Log de leituras auditadas, encadeado por hash (deteccao de adulteracao interna)."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []

    def append(self, entry: Dict[str, Any]) -> str:
        prev = self.records[-1]["hash"] if self.records else ""
        body = dict(entry, prev=prev)
        rec = dict(body, hash=b64u(sha256(jcs.canonicalize(body))))
        self.records.append(rec)
        return rec["hash"]

    def verify(self) -> bool:
        prev = ""
        for rec in self.records:
            body = {k: v for k, v in rec.items() if k != "hash"}
            if body.get("prev") != prev or rec["hash"] != b64u(
                sha256(jcs.canonicalize(body))
            ):
                return False
            prev = rec["hash"]
        return True

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec) + "\n")

    @classmethod
    def load(cls, path: str) -> "AuditLog":
        log = cls()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                log.records = [json.loads(line) for line in fh if line.strip()]
        return log


# -- lado do sidecar --------------------------------------------------------------------
class OrgTrust:
    def __init__(self, cfg: Dict[str, Any], http: HttpClient, clock: Any) -> None:
        self.http, self.clock = http, clock
        self.anchors: Dict[str, Dict[str, Any]] = {}
        self.own_org: Optional[str] = None
        self.own_descriptor: Optional[Dict[str, Any]] = None
        self._own_attestation: Optional[Dict[str, Any]] = None
        trust_cfg = cfg.get("trust") or {}
        self.revocation_max_cache_age = int(
            trust_cfg.get("revocation_max_cache_age", REVOCATIONS_DEFAULT)
        )
        if self.revocation_max_cache_age > REVOCATIONS_MAX:
            self.revocation_max_cache_age = REVOCATIONS_MAX
        own = cfg.get("org")
        if own:
            desc_doc = own.get("descriptor")
            if not isinstance(desc_doc, dict):
                raise SeloError("bad_config", "org.descriptor ausente")
            body = desc_doc.get("body", {})
            anchor = unb64u(body.get("anchor_pub", ""))
            self.own_descriptor = verify_doc(anchor, "org", desc_doc)
            self.own_org = self.own_descriptor["name"]
            self.anchors[self.own_org] = {
                "anchor_pub": anchor,
                "revocations_url": self.own_descriptor["revocations_url"],
            }
            self._own_attestation = own.get("attestation")
        for entry in (cfg.get("trust") or {}).get("orgs") or []:
            try:
                name, anchor, url = (
                    entry["name"],
                    unb64u(entry["anchor_pub"]),
                    entry["revocations_url"],
                )
            except (KeyError, TypeError):
                raise SeloError(
                    "bad_config", "trust.orgs: name, anchor_pub e revocations_url"
                ) from None
            if name in self.anchors and self.anchors[name]["anchor_pub"] != anchor:
                raise SeloError("bad_config", f"ancora conflitante para {name}")
            self.anchors[name] = {"anchor_pub": anchor, "revocations_url": url}
        self._lists: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def own_attestations(self) -> List[Dict[str, Any]]:
        return [self._own_attestation] if self._own_attestation else []

    def _valid_attestation(self, doc: Any, agent_id: str, now: float) -> Optional[str]:
        if not isinstance(doc, dict) or not isinstance(doc.get("body"), dict):
            return None
        org = doc["body"].get("org")
        anchor = self.anchors.get(org)
        if anchor is None:
            return None  # ancora nao configurada: atestacao ignorada
        body = verify_doc(anchor["anchor_pub"], "attestation", doc)
        if body.get("agent_id") != agent_id:
            raise SeloError("bad_attestation", "atestacao de outro agente")
        iat, exp = body.get("iat"), body.get("exp")
        if (
            type(iat) is not int
            or type(exp) is not int
            or not (iat <= now + CLOCK_SKEW and now < exp)
        ):
            raise SeloError("bad_attestation", "atestacao fora da validade")
        return org

    def revocations(self, org: str, now: float) -> Dict[str, Any]:
        """Lista de revogacao fresca da organizacao, ou falha fechada (`revocations_stale`)."""
        with self._lock:
            cached = self._lists.get(org)
        if (
            cached
            and cached["iat"] <= now + CLOCK_SKEW
            and now <= cached["next_update"]
            and now - cached["iat"] <= self.revocation_max_cache_age
        ):
            return cached
        anchor = self.anchors[org]
        try:
            status, doc = self.http.json("GET", anchor["revocations_url"])
            if status != 200:
                raise SeloError("revocations_stale", f"HTTP {status}")
            body = verify_doc(anchor["anchor_pub"], "revocations", doc)
        except SeloError as e:
            raise SeloError("revocations_stale", f"{org}: {e.code}") from None
        if (
            body.get("org") != org
            or type(body.get("iat")) is not int
            or type(body.get("next_update")) is not int
            or not body["iat"] <= now + CLOCK_SKEW
            or not now <= body["next_update"]
            or body["next_update"] - body["iat"] > REVOCATIONS_MAX
            or not isinstance(body.get("revoked"), list)
        ):
            raise SeloError("revocations_stale", f"{org}: lista vencida ou invalida")
        with self._lock:
            prev = self._lists.get(org)
            if prev and body["seq"] < prev["seq"]:
                raise SeloError(
                    "revocations_stale", f"{org}: lista mais antiga que a conhecida"
                )
            self._lists[org] = body
        return body

    def attested_org(self, info: CardInfo, now: float) -> Optional[str]:
        for doc in info.attestations:
            org = self._valid_attestation(doc, info.agent_id, now)
            if org is None:
                continue
            if info.agent_id in self.revocations(org, now)["revoked"]:
                raise SeloError("peer_revoked", f"{info.agent_id} revogado por {org}")
            return org
        return None

    def escrow_org(self, peer_trust: Any) -> Optional[str]:
        """Escrow so entre membros da propria organizacao, com o modo ligado (secao 11)."""
        if (
            self.own_org is None
            or self.own_descriptor is None
            or not self.own_descriptor.get("escrow", {}).get("enabled")
            or peer_trust.org != self.own_org
            or not self._own_attestation
        ):
            return None
        return self.own_org

    def escrow_target(self, org: str) -> EscrowTarget:
        assert self.own_descriptor is not None and org == self.own_org
        return EscrowTarget(org, unb64u(self.own_descriptor["escrow"]["agree_pub"]))


# -- CLI ------------------------------------------------------------------------------------
def add_cli(sub: Any) -> None:
    p = sub.add_parser("org", help="organizacao: atestacao, revogacao, escrow")
    osub = p.add_subparsers(dest="org_cmd", required=True)
    q = osub.add_parser("init")
    q.add_argument("--dir", required=True)
    q.add_argument("--name", required=True)
    q.add_argument("--revocations-url", required=True)
    q.add_argument("--escrow", action="store_true")
    q.add_argument("--keystore", default="auto")
    for name in (
        "descriptor",
        "anchor",
        "serve",
        "attest",
        "revoke",
        "audit",
        "shares",
    ):
        q = osub.add_parser(name)
        q.add_argument("--dir", required=True)
        q.add_argument("--keystore", default="auto")
        if name == "serve":
            q.add_argument("--host", default="127.0.0.1")
            q.add_argument("--port", type=int, default=0)
            q.add_argument("--tls-cert")
            q.add_argument("--tls-key")
            q.add_argument("--ttl", type=int, default=REVOCATIONS_DEFAULT)
        if name in ("attest", "revoke"):
            q.add_argument("--agent-id", required=True)
        if name == "attest":
            q.add_argument("--roles", default="agent")
        if name == "audit":
            q.add_argument("--capture", required=True)
            q.add_argument("--auditor", required=True)
            q.add_argument("--reason", required=True)
        if name == "shares":
            q.add_argument("--threshold", type=int, required=True)
            q.add_argument("--count", type=int, required=True)


def run_cli(a: Any) -> int:
    from .keystore import open_keystore

    ks = open_keystore(a.keystore, a.dir, "org")
    now = time.time()
    if a.org_cmd == "init":
        org = Organization.create(a.name, a.revocations_url, a.escrow)
        ks.store("org_master", org.master)
        org.save_state(a.dir)
        print(
            json.dumps(
                {"anchor": org.anchor_entry(), "descriptor": org.descriptor(now)},
                indent=2,
            )
        )
        return 0
    org = Organization.load(a.dir, ks)
    if a.org_cmd == "descriptor":
        print(json.dumps(org.descriptor(now), indent=2))
    elif a.org_cmd == "anchor":
        print(json.dumps(org.anchor_entry(), indent=2))
    elif a.org_cmd == "attest":
        print(json.dumps(org.attest(a.agent_id, now, a.roles.split(",")), indent=2))
    elif a.org_cmd == "revoke":
        org.revoke(a.agent_id)
        org.save_state(a.dir)
        print(json.dumps(org.revocation_list(now), indent=2))
    elif a.org_cmd == "shares":
        print(json.dumps(org.master_shares(a.threshold, a.count), indent=2))
    elif a.org_cmd == "audit":
        with open(a.capture, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        opened = org.open_captured(records, a.auditor, a.reason)
        org.save_state(a.dir)
        print(json.dumps(opened, indent=2, ensure_ascii=False))
    elif a.org_cmd == "serve":
        import ssl

        ctx = None
        if a.tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(a.tls_cert, a.tls_key)
        from .net import is_loopback_host

        if not is_loopback_host(a.host) and ctx is None:
            raise SeloError("tls_required", f"recusado: {a.host} sem TLS")
        srv = org.serve(a.host, a.port, ctx, ttl=a.ttl, reload_from=a.dir)
        print(
            "READY "
            + json.dumps(
                {"url": f"{'https' if ctx else 'http'}://{a.host}:{srv.port}"}
            ),
            flush=True,
        )
        threading.Event().wait()
    return 0
