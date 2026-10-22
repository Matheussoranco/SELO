"""Agente SELO: cliente e servidor ao mesmo tempo.

Servidor (`handle`): autentica+decifra -> anti-replay -> valida argumentos -> contaminacao do
contexto -> token de capacidade -> executa handler local -> responde com carimbo de proveniencia.
Cliente (`call`): cifra para a chave de acordo da epoca do destinatario, anexa o contexto
(carimbos) e valida/registra o carimbo do resultado.

Nenhuma mensagem instala codigo ou concede permissao: handlers sao registrados localmente a
partir de manifestos admitidos pela organizacao.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric import ed25519

from .envelope import DEFAULT_TTL, Opened, open_envelope, peek_header, seal
from .keys import EpochKeys, OrgParams, verify_epoch_entry
from .manifest import ManifestStore, manifest_hash, validate_args
from .provenance import Session, effective_taint, make_stamp, verify_stamp
from .tokens import Token, TokenContext, mint, verify as verify_token
from .util import SeloError, b64d, check_id, content_hash

Directory = Callable[[str, int], Dict[str, Any]]            # (agent_id, epoch) -> EpochEntry
Send = Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]   # (entry_body, envelope) -> resp
CALL_FIELDS = {"t", "cap", "args", "token", "ctx", "entry", "sender", "recipient"}


@dataclass
class Capability:
    doc: Dict[str, Any]                  # manifesto assinado e admitido
    manifest: Dict[str, Any]
    mhash: str
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    bundle: Any = None                   # (doc, prova de inclusao, STH) para servir no catalogo


class RemoteError(SeloError):
    """Erro devolvido (cifrado e autenticado) pelo servidor remoto."""


class Agent:
    def __init__(self, *, agent_id: str, org: OrgParams, sig_sk: ed25519.Ed25519PrivateKey,
                 cert: Dict[str, Any], keys: EpochKeys, directory: Directory,
                 entry_provider: Callable[[str], Dict[str, Any]],
                 clock: Callable[[], float] = time.time, revoked: Optional[set] = None,
                 token_root: Optional[bytes] = None,
                 extra_forbid: Optional[Dict[str, Set[str]]] = None,
                 manifests: Optional[ManifestStore] = None, db: str = ":memory:") -> None:
        self.id = check_id(agent_id)
        self.org, self.sig_sk, self.cert, self.keys = org, sig_sk, cert, keys
        self.directory, self.entry_provider, self.clock = directory, entry_provider, clock
        self.revoked = revoked if revoked is not None else set()
        self.token_root = token_root
        self.extra_forbid = extra_forbid or {}
        self.manifests = manifests or ManifestStore(org, clock, revoked=self.revoked)
        self.caps: Dict[str, Capability] = {}
        self._uses: Dict[str, int] = {}
        self._entries: Dict[tuple, Dict[str, Any]] = {}
        self._my_entry: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS seen "
                         "(sender TEXT, msg TEXT, exp INTEGER, PRIMARY KEY(sender, msg))")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------------ utilitarios
    def now(self) -> int:
        return int(self.clock())

    def _sync(self) -> int:
        epoch = self.org.epoch_of(self.now())
        if epoch > self.keys.epoch:
            self.keys.advance_to(epoch)
        return epoch

    def my_entry(self) -> Dict[str, Any]:
        epoch = self._sync()
        if self._my_entry is None or self._my_entry["b"]["epoch"] != epoch:
            self._my_entry = self.entry_provider(self.id)
        return self._my_entry

    def remote_entry(self, agent_id: str) -> Dict[str, Any]:
        epoch = self._sync()
        key = (agent_id, epoch)
        if key not in self._entries:
            self._entries[key] = self.directory(agent_id, epoch)
        body = verify_epoch_entry(self.org, self._entries[key], self.now())
        if body["id"] != agent_id:
            raise SeloError("entry_mismatch")
        return body

    # ------------------------------------------------------------------ capacidades
    def register(self, bundle: Any, handler: Callable[[Dict[str, Any]], Dict[str, Any]],
                 upgrade: bool = False) -> str:
        """Registra uma capacidade local a partir de (manifesto admitido, prova, STH)."""
        doc, proof, sth = bundle
        m = self.manifests.add(doc, proof, sth)
        if m["name"] in self.caps and not upgrade:
            raise SeloError("duplicate_capability")
        self.caps[m["name"]] = Capability(doc, m, manifest_hash(m), handler, bundle)
        return manifest_hash(m)

    def mint(self, cap: str, caveats=(), bearer: bool = False) -> Token:
        """Emite um token de capacidade. Por padrao exige caveat `holder` (nada de token ao portador)."""
        if self.token_root is None or cap not in self.caps:
            raise SeloError("cannot_mint")
        if not bearer and not any("holder" in c for c in caveats):
            raise SeloError("holder_required")
        return mint(self.token_root, cap, caveats)

    def catalog(self) -> List[Any]:
        """Manifestos assinados + provas de inclusao: publico, nao carrega segredos."""
        return [c.bundle for c in self.caps.values()]

    def sensitive_args(self, cap: str) -> Optional[List[str]]:
        """Argumentos marcados `x-selo-sensitive` no manifesto conhecido da capacidade (ou None)."""
        for m in self.manifests.by_hash.values():
            if m["name"] == cap:
                props = m["schema"].get("properties", {})
                marked = [k for k, rule in props.items() if rule.get("x-selo-sensitive")]
                return marked or None
        return None

    def learn(self, bundle: Any, approve: Optional[Callable[[str, str], bool]] = None) -> Dict[str, Any]:
        """Aprende um manifesto remoto; se o nome ja estava fixado e o hash mudou, exige aprovacao."""
        m = self.manifests.add(*bundle)
        if m["name"] in self.manifests.pinned:
            self.manifests.check_pin(m["name"], manifest_hash(m), approve)
        return m

    # ------------------------------------------------------------------ servidor
    def _reserve(self, opened: Opened) -> None:
        h = opened.header
        with self._lock, self._db:
            self._db.execute("DELETE FROM seen WHERE exp < ?", (self.now(),))
            try:
                self._db.execute("INSERT INTO seen VALUES (?, ?, ?)", (h["sender"], h["msg"], h["exp"]))
            except sqlite3.IntegrityError:
                raise SeloError("replay") from None

    def handle(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Processa uma requisicao; devolve o envelope de resposta (cifrado para o remetente).

        Levanta SeloError se a mensagem nao puder ser autenticada/decifrada (sem resposta).
        """
        now = self.now()
        header = peek_header(envelope)
        self._sync()
        opened = open_envelope(envelope, org=self.org, agree_sk=self.keys.agree_key(header["epoch"]),
                               my_id=self.id, now=now, revoked=self.revoked)
        self._reserve(opened)
        entry = self._reply_entry(opened)
        try:
            reply = self._execute(opened, now)
        except SeloError as error:
            reply = {"t": "error", "re": header["msg"], "code": error.code, "detail": error.detail[:200]}
        except Exception:                                       # nunca vazar detalhes internos
            reply = {"t": "error", "re": header["msg"], "code": "internal_error", "detail": ""}
        return self._seal_to(entry, reply)

    def _reply_entry(self, opened: Opened) -> Dict[str, Any]:
        entry = opened.body.get("entry")
        body = verify_epoch_entry(self.org, entry, self.now())
        if body["id"] != opened.header["sender"]:
            raise SeloError("entry_mismatch")
        return body

    def _seal_to(self, entry: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
        return seal(org=self.org, sender_id=self.id, sender_sk=self.sig_sk, sender_cert=self.cert,
                    recipient_id=entry["id"], recipient_epoch=entry["epoch"],
                    recipient_agree_pub=b64d(entry["agree_pub"]), body=body, now=self.now())

    def _execute(self, opened: Opened, now: int) -> Dict[str, Any]:
        body = opened.body
        if body.get("t") != "call" or set(body) != CALL_FIELDS:
            raise SeloError("bad_request")
        sender = opened.header["sender"]
        capability = self.caps.get(body["cap"]) if isinstance(body["cap"], str) else None
        if capability is None:
            raise SeloError("unknown_capability")
        m = capability.manifest
        try:
            validate_args(m["schema"], body["args"])
        except ValueError as error:
            raise SeloError("invalid_arguments", str(error)) from None

        ctx = body["ctx"]
        if (not isinstance(ctx, dict) or set(ctx) != {"sid", "stamps", "endorsements", "scope"}
                or not isinstance(ctx["sid"], str) or not isinstance(ctx["stamps"], list)
                or not isinstance(ctx["endorsements"], list) or ctx["scope"] not in ("full", "args")):
            raise SeloError("bad_request", "ctx")
        if m["context"] == "full" and ctx["scope"] != "full":
            raise SeloError("full_context_required", m["name"])
        taint = effective_taint(self.org, ctx["stamps"], ctx["endorsements"], now,
                                self.manifests.get, self.revoked, sid=ctx["sid"], cap=m["name"])
        blocked = taint & (set(m["forbid_taint"]) | self.extra_forbid.get(m["name"], set()))
        if blocked:
            raise SeloError("tainted_context", ",".join(sorted(blocked)))

        if self.token_root is None:
            raise SeloError("no_tokens")
        token = Token.from_dict(body["token"])
        verify_token(self.token_root, token, TokenContext(
            sender=sender, cap=m["name"], manifest_hash=capability.mhash, now=now,
            args=body["args"], taint=taint, uses=lambda i: self._uses.get(i, 0)))

        try:
            result = capability.handler(body["args"])
        except ValueError as error:
            raise SeloError("invalid_arguments", str(error)) from None
        with self._lock:
            self._uses[token.ident] = self._uses.get(token.ident, 0) + 1
        stamp = make_stamp(origin_id=self.id, sk=self.sig_sk, cert=self.cert, content=result,
                           taint=taint | set(m["taint_out"]), ts=now, kind="result",
                           cap=m["name"], manifest=capability.mhash)
        return {"t": "result", "re": opened.header["msg"], "result": result, "stamp": stamp}

    # ------------------------------------------------------------------ cliente
    def call(self, recipient_id: str, cap: str, args: Dict[str, Any], token: Token,
             session: Session, send: Send, ttl: int = DEFAULT_TTL, scope: str = "full",
             cite_only: Optional[Any] = None) -> Dict[str, Any]:
        """`scope="full"` cita todo o contexto; `scope="args"` cita so os itens que originaram os
        argumentos (menos bloqueios falsos; depende do casamento textual do harness)."""
        target = self.remote_entry(recipient_id)
        if scope == "args" and cite_only is None:
            cite_only = self.sensitive_args(cap)
        stamps = session.stamps if scope == "full" else session.cite_for(args, cite_only)
        request = {"t": "call", "cap": cap, "args": args, "token": token.to_dict(),
                   "ctx": {"sid": session.sid, "stamps": stamps, "scope": scope,
                           "endorsements": session.endorsements},
                   "entry": self.my_entry()}
        envelope = seal(org=self.org, sender_id=self.id, sender_sk=self.sig_sk,
                        sender_cert=self.cert, recipient_id=recipient_id,
                        recipient_epoch=target["epoch"], recipient_agree_pub=b64d(target["agree_pub"]),
                        body=request, now=self.now(), ttl=ttl)
        sent_id = envelope["h"]["msg"]
        response = send(target, envelope)

        header = peek_header(response)
        opened = open_envelope(response, org=self.org, agree_sk=self.keys.agree_key(header["epoch"]),
                               my_id=self.id, now=self.now(), revoked=self.revoked)
        body = opened.body
        if header["sender"] != recipient_id or body.get("re") != sent_id:
            raise SeloError("response_mismatch")
        if body.get("t") == "error":
            raise RemoteError(str(body.get("code")), str(body.get("detail", "")))
        if body.get("t") != "result" or "result" not in body or "stamp" not in body:
            raise SeloError("response_mismatch")
        stamp = verify_stamp(self.org, body["stamp"], self.revoked)
        if (stamp["origin"] != recipient_id or stamp["h"] != content_hash(body["result"])
                or stamp["cap"] != cap):
            raise SeloError("stamp_mismatch")
        session.observe(body["stamp"], body["result"])
        return body["result"]
