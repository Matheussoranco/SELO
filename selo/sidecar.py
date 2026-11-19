"""Sidecar SELO: um processo por agente (especificacao, secao 2).

Responsabilidades: chaves (cofre), Agent Card, verificacao e decifragem de tudo que chega,
anti-replay, politica de confianca, entrega ao agente local e envio para os pares.
"""

from __future__ import annotations

import copy
import json
import os
import ssl
import threading
import time
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from . import channel, envelope
from .card import WELL_KNOWN, CardInfo, build_card, local_view
from .config import from_dict
from .crypto.primitives import b64u, unb64u
from .errors import SeloError
from .identity import Identity
from .keystore import KeyStore, open_keystore
from .local import LocalServer
from .net import HttpClient, HttpServer, Request, Response, is_loopback_host
from .peers import PeerDirectory, PeerTrust, TrustPolicy
from .store import Store

IDENTITY_KEY = "identity"
ERROR_STATUS = {"replay": 409, "unknown_session": 404, "body_too_large": 413}


def _rpc_error(rid: Any, e: SeloError) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": e.jsonrpc_error()}


def _check_rpc_request(rpc: Any) -> Tuple[Any, str]:
    if (
        not isinstance(rpc, dict)
        or rpc.get("jsonrpc") != "2.0"
        or not isinstance(rpc.get("method"), str)
    ):
        raise SeloError("bad_request", "requisicao JSON-RPC 2.0 invalida")
    return rpc.get("id"), rpc["method"]


class Sidecar:
    def __init__(
        self,
        cfg: Dict[str, Any],
        keystore: Optional[KeyStore] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.cfg = (
            from_dict({k: v for k, v in cfg.items() if k != "_path"})
            if "_path" not in cfg
            else cfg
        )
        self.name = self.cfg["name"]
        offset = float(self.cfg.get("clock_offset") or 0)
        self.clock = clock or (lambda: time.time() + offset)
        self.state_dir = os.path.abspath(self.cfg["state_dir"])
        os.makedirs(self.state_dir, exist_ok=True)
        self.keystore = keystore or open_keystore(
            self.cfg["keystore"]["backend"], self.state_dir, self.name
        )
        self._id_lock = threading.RLock()
        self.identity, data_key = self._load_identity()
        self.store = Store(os.path.join(self.state_dir, "state.sqlite3"), data_key)
        self.http = HttpClient(self.cfg["tls"].get("ca_file"))
        self.orgs = self._make_org_trust()
        self.trust = TrustPolicy(self.cfg, self.orgs)
        self.peers = PeerDirectory(
                    self.store,
                    self.http,
                    self.clock,
                    self.trust,
                    int(self.cfg["card"]["max_card_age"]),
                    preconfigured_pins=self.cfg.get("trust", {}).get("pins"),
                )
        self.hook = self._load_policy_hook()
        self.base_url = ""
        self._card: Optional[Dict[str, Any]] = None
        self._card_lock = threading.Lock()
        self._capture_lock = threading.Lock()
        self.public: Optional[HttpServer] = None
        self.intake: Optional[HttpServer] = None
        self.local: Optional[LocalServer] = None
        self._extensions_init()

    # -- extensoes de tickets posteriores (sessoes, push, organizacao, politica) ------------
    def _extensions_init(self) -> None:
        from .sessions import SessionManager

        self.sessions = SessionManager(self)

    def _make_org_trust(self) -> Any:
        if not self.cfg.get("org") and not self.cfg["trust"].get("orgs"):
            return None
        from .org import OrgTrust

        return OrgTrust(self.cfg, self.http, self.clock)

    def _load_policy_hook(self) -> Any:
        from .policy import load_hook

        return load_hook(self.cfg.get("policy"))

    # -- identidade -----------------------------------------------------------------------
    def _load_identity(self) -> Tuple[Identity, bytes]:
        raw = self.keystore.load(IDENTITY_KEY)
        if raw is None:
            ident = Identity.generate(int(self.clock()))
            data_key = os.urandom(32)
            self._save_identity(ident, data_key)
            return ident, data_key
        d = json.loads(raw)
        return Identity.from_secret(d["identity"]), unb64u(d["data_key"])

    def _save_identity(self, ident: Identity, data_key: bytes) -> None:
        self.keystore.store(
            IDENTITY_KEY,
            json.dumps(
                {"identity": ident.to_secret(), "data_key": b64u(data_key)}
            ).encode(),
        )

    def rotate_keys(self) -> None:
        with self._id_lock:
            self.identity.rotate(int(self.clock()))
            self._save_identity(self.identity, self.store._data_key)
            self._card = None

    def revoke_identity(self) -> None:
        with self._id_lock:
            self.identity.revoke(int(self.clock()))
            self._save_identity(self.identity, self.store._data_key)
            self._card = None

    # -- ciclo de vida --------------------------------------------------------------------
    def start(self) -> "Sidecar":
        pub = self.cfg["public"]
        host, tls = pub["host"], pub.get("tls")
        if not is_loopback_host(host) and not tls:
            raise SeloError(
                "tls_required",
                f"recusado: {host} nao e loopback e nao ha TLS configurado",
            )
        ctx = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(tls["cert"], tls["key"])
        self.public = HttpServer(
            host, int(pub["port"]), self.handle_public, ctx
        ).start()
        scheme = "https" if tls else "http"
        shown = host if ":" not in host else f"[{host}]"
        self.base_url = (
            pub.get("url") or f"{scheme}://{shown}:{self.public.port}"
        ).rstrip("/")
        self.intake = HttpServer("127.0.0.1", 0, self.handle_intake).start()
        loc = self.cfg["local"]
        self.local = LocalServer(
            self,
            self.state_dir,
            self.name,
            loc.get("mode", "auto"),
            int(loc.get("port") or 0),
        ).start()
        return self

    def stop(self) -> None:
        for srv in (self.local, self.public, self.intake):
            try:
                if srv:
                    srv.stop()
            except Exception:
                pass
        self.store.close()

    def ready_info(self) -> Dict[str, Any]:
        return {
            "agent_id": self.identity.agent_id,
            "public_url": self.base_url,
            "local": self.local.info if self.local else None,
            "intake_url": (
                f"http://127.0.0.1:{self.intake.port}" if self.intake else None
            ),
        }

    # -- Agent Card -----------------------------------------------------------------------
    def card(self) -> Dict[str, Any]:
        now = int(self.clock())
        with self._card_lock:
            c = self._card
            if c is not None:
                p = c["capabilities"]["extensions"][0]["params"]
                if now < p["iat"] + (p["exp"] - p["iat"]) // 2:
                    return c
            cc = self.cfg["card"]
            self._card = build_card(
                self.identity,
                self.base_url,
                name=self.name,
                description=cc.get("description") or "",
                skills=cc.get("skills"),
                attestations=self._attestations(),
                iat=now,
                validity=int(cc.get("validity") or 86400),
            )
            return self._card

    def _attestations(self) -> list:
        return self.orgs.own_attestations() if self.orgs is not None else []

    # -- captura de trafego (auditoria) ---------------------------------------------------
    def capture(self, direction: str, kind: str, data: Any, **extra: Any) -> None:
        path = self.cfg.get("capture_path")
        if not path:
            return
        rec = {
            "t": int(self.clock()),
            "dir": direction,
            "kind": kind,
            "data": data,
            **extra,
        }
        with self._capture_lock, open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    # -- servidor publico -----------------------------------------------------------------
    def handle_public(self, req: Request) -> Response:
        p = req.path
        if req.method == "GET" and p == WELL_KNOWN:
            return Response(200, self.card())
        if req.method == "POST":
            if p == "/selo/v1/envelope":
                return self._guard(self.handle_envelope, req)
            if p == "/selo/v1/session":
                return self._guard(self.sessions.handle_handshake, req)
            if p.startswith("/selo/v1/session/"):
                return self._guard(
                    self.sessions.handle_message, req, p[len("/selo/v1/session/") :]
                )
            if p.startswith("/selo/v1/push/"):
                return self._guard(
                    self.handle_push_delivery, req, p[len("/selo/v1/push/") :]
                )
            return self._plaintext_refused(req)
        return Response(404, {"error": "not_found"})

    def _guard(self, fn: Callable[..., Response], req: Request, *args: Any) -> Response:
        try:
            return fn(req, *args)
        except SeloError as e:
            return Response(ERROR_STATUS.get(e.code, 400), {"error": e.code})

    def _plaintext_refused(self, req: Request) -> Response:
        from . import EXTENSION_URI

        rid = None
        try:
            body = req.json()
            rid = body.get("id") if isinstance(body, dict) else None
        except SeloError:
            pass
        err = SeloError("extension_required", data={"extension": EXTENSION_URI})
        return Response(200, _rpc_error(rid, err))

    # -- envelope de entrada --------------------------------------------------------------
    def resolve_sender(self, h: Dict[str, Any]) -> Tuple[CardInfo, PeerTrust]:
        return self.resolve_peer_at(h["sender_card"], h["sender"], h["sender_seq"])

    def resolve_peer_at(
        self, url: str, agent_id: str, seq: int
    ) -> Tuple[CardInfo, PeerTrust]:
        """Card do par; busca de novo se ele usa uma chave mais nova que a do Card em cache."""
        info, trust = self.peers.get(url, expected_id=agent_id)
        if seq > info.kel.seq:
            info, trust = self.peers.get(url, expected_id=agent_id, refresh=True)
        return info, trust

    def escrow_org_for(self, peer_trust: PeerTrust) -> Optional[str]:
        """Organizacao cujo escrow se aplica a conversa com este par (secao 11), ou None."""
        if self.orgs is None:
            return None
        return self.orgs.escrow_org(peer_trust)

    def escrow_target(self, peer_trust: PeerTrust) -> Any:
        org = self.escrow_org_for(peer_trust)
        return self.orgs.escrow_target(org) if org else None

    def open_incoming(
            self, env: Any, expect_type: str, expected_sender: Optional[str] = None
        ) -> Tuple[envelope.Opened, PeerTrust]:
            trusts: Dict[str, PeerTrust] = {}

            def resolve(h: Dict[str, Any]) -> CardInfo:
                if expected_sender is not None and h["sender"] != expected_sender:
                    raise SeloError("identity_mismatch", "resposta de outro agente")
                info, trust = self.resolve_sender(h)
                trusts["t"] = trust
                return info

            def get_cached_key(h: Dict[str, Any]) -> Optional[bytes]:
                return self.peers.get_cached_sender_key(
                    h["sender"], h["sender_card"], h["sender_seq"]
                )

            opened = envelope.open_envelope(
                env,
                me=self.identity,
                now=self.clock(),
                resolve_sender=resolve,
                replay=lambda s, m, exp: self.store.check_replay(s, m, exp, self.clock()),
                escrow_org=lambda _info: self.escrow_org_for(trusts["t"]),
                expect_type=expect_type,
                get_cached_sender_key=get_cached_key,
            )
            return opened, trusts["t"]

    def handle_envelope(self, req: Request) -> Response:
        env = req.json()
        self.capture("in", "envelope", env)
        opened, trust = self.open_incoming(env, "req")
        rpc = opened.body.get("rpc")
        try:
            rid, method = _check_rpc_request(rpc)
            if channel.is_streaming(method):
                raise SeloError("bad_request", "streaming exige sessao")
            result = self.dispatch_inbound(rpc, opened.sender, trust)
        except SeloError as e:
            result = _rpc_error(rpc.get("id") if isinstance(rpc, dict) else None, e)
        resp = envelope.seal(
            sender=self.identity,
            sender_card_url=self.base_url,
            recipient=opened.sender,
            body={"rpc": result},
            t="resp",
            now=self.clock(),
            re=opened.header["msg"],
            escrow=self.escrow_target(trust),
        )
        self.capture("out", "envelope", resp)
        return Response(200, resp)

    # -- entrega ao agente local ----------------------------------------------------------
    def _agent_headers(self, sender: CardInfo, trust: PeerTrust) -> Dict[str, str]:
        h = {
            "X-Selo-Sender": sender.agent_id,
            "X-Selo-Org": trust.org or "",
            "A2A-Version": "1.0",
        }
        tok = self.cfg["agent"].get("inbound_token")
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    def _agent_url(self) -> str:
        url = self.cfg["agent"].get("url")
        if not url:
            raise SeloError("agent_unavailable", "agent.url nao configurado")
        return url

    def dispatch_inbound(
        self, rpc: Dict[str, Any], sender: CardInfo, trust: PeerTrust
    ) -> Dict[str, Any]:
        """Politica, reescrita de push e entrega ao agente local (nao streaming)."""
        rid, method = _check_rpc_request(rpc)
        rpc = self.before_inbound(rpc, sender, trust)
        try:
            status, body = self.http.json(
                "POST", self._agent_url(), rpc, self._agent_headers(sender, trust)
            )
        except SeloError as e:
            return _rpc_error(rid, SeloError("agent_unavailable", e.detail))
        if not isinstance(body, dict):
            return _rpc_error(rid, SeloError("agent_unavailable", f"HTTP {status}"))
        return self.after_inbound(rpc, body, sender, trust)

    def stream_inbound(
        self, rpc: Dict[str, Any], sender: CardInfo, trust: PeerTrust
    ) -> Iterator[Dict[str, Any]]:
        """Entrega uma requisicao de streaming ao agente e itera as respostas JSON-RPC."""
        rid, _method = _check_rpc_request(rpc)
        rpc = self.before_inbound(rpc, sender, trust)
        r = self.http.stream(
            "POST", self._agent_url(), rpc, self._agent_headers(sender, trust)
        )
        if not r.is_sse:
            raw = r.read_all()
            try:
                yield self.after_inbound(rpc, json.loads(raw), sender, trust)
            except ValueError:
                yield _rpc_error(rid, SeloError("agent_unavailable"))
            return
        for data in r.events():
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            yield self.after_inbound(rpc, ev, sender, trust)

    def before_inbound(
        self, rpc: Dict[str, Any], sender: CardInfo, trust: PeerTrust
    ) -> Dict[str, Any]:
        self.hook.check("inbound", "request", sender.agent_id, trust.org, rpc)
        return self.rewrite_push_inbound(rpc, sender)

    def after_inbound(
        self,
        rpc: Dict[str, Any],
        resp: Dict[str, Any],
        sender: CardInfo,
        trust: PeerTrust,
    ) -> Dict[str, Any]:
        try:
            self.hook.check(
                "inbound",
                "response",
                sender.agent_id,
                trust.org,
                resp,
                method=rpc.get("method"),
            )
        except SeloError as e:
            return _rpc_error(rpc.get("id"), e)
        return resp

    # -- envio ----------------------------------------------------------------------------
    def resolve_ref(self, ref: str) -> str:
        url = self.cfg["peers"].get(ref, ref)
        if not url.startswith(("http://", "https://")):
            raise SeloError("unknown_peer", ref)
        return url

    def call(self, peer: str, rpc: Dict[str, Any]) -> Dict[str, Any]:
        """LocalApi: envia uma requisicao nao streaming a um par e devolve a resposta JSON-RPC."""
        rid = rpc.get("id") if isinstance(rpc, dict) else None
        try:
            _rid, method = _check_rpc_request(rpc)
            if channel.is_streaming(method):
                raise SeloError("bad_request", "use stream para metodos de streaming")
            info, trust = self.peers.get(self.resolve_ref(peer))
            rpc = self.before_outbound(rpc, info, trust)
            resp = self.sessions.call(info, trust, rpc)
            return self.after_outbound(rpc, resp, info, trust)
        except SeloError as e:
            return _rpc_error(rid, e)

    def stream(self, peer: str, rpc: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        rid = rpc.get("id") if isinstance(rpc, dict) else None
        try:
            _check_rpc_request(rpc)
            info, trust = self.peers.get(self.resolve_ref(peer))
            rpc = self.before_outbound(rpc, info, trust)
            for ev in self.sessions.stream(info, trust, rpc):
                yield self.after_outbound(rpc, ev, info, trust)
        except SeloError as e:
            yield _rpc_error(rid, e)

    def before_outbound(
        self, rpc: Dict[str, Any], info: CardInfo, trust: PeerTrust
    ) -> Dict[str, Any]:
        self.hook.check("outbound", "request", info.agent_id, trust.org, rpc)
        return self.rewrite_push_outbound(rpc, info)

    def after_outbound(
        self,
        rpc: Dict[str, Any],
        resp: Dict[str, Any],
        info: CardInfo,
        trust: PeerTrust,
    ) -> Dict[str, Any]:
        try:
            self.hook.check(
                "outbound",
                "response",
                info.agent_id,
                trust.org,
                resp,
                method=rpc.get("method"),
            )
        except SeloError as e:
            return _rpc_error(rpc.get("id"), e)
        return resp

    def send_envelope(
        self,
        info: CardInfo,
        trust: PeerTrust,
        body: Dict[str, Any],
        t: str = "req",
        path: str = "/selo/v1/envelope",
    ) -> Dict[str, Any]:
        env = envelope.seal(
            sender=self.identity,
            sender_card_url=self.base_url,
            recipient=info,
            body=body,
            t=t,
            now=self.clock(),
            escrow=self.escrow_target(trust),
        )
        self.capture("out", "envelope", env)
        status, reply = self.http.json("POST", info.base_url + path, env)
        if status != 200 or not isinstance(reply, dict) or "error" in reply:
            code = reply.get("error") if isinstance(reply, dict) else None
            raise SeloError(code or "peer_error", f"HTTP {status}")
        self.capture("in", "envelope", reply)
        opened, _trust = self.open_incoming(
            reply, "resp", expected_sender=info.agent_id
        )
        if opened.header.get("re") != env["h"]["msg"]:
            raise SeloError("bad_response", "resposta nao corresponde ao pedido")
        return opened.body

    def call_envelope(
        self, info: CardInfo, trust: PeerTrust, rpc: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            body = self.send_envelope(info, trust, {"rpc": rpc})
        except SeloError as e:
            if e.code != "wrong_recipient":
                raise
            # o par girou a chave e a janela passou: busca o Card novo e tenta uma vez
            info, trust = self.peers.get(
                info.base_url, expected_id=info.agent_id, refresh=True
            )
            body = self.send_envelope(info, trust, {"rpc": rpc})
        resp = body.get("rpc")
        if not isinstance(resp, dict):
            raise SeloError("bad_response", "resposta sem rpc")
        return resp

    # -- LocalApi -------------------------------------------------------------------------
    def peer_card(self, peer: str, local_url: Optional[str]) -> Dict[str, Any]:
        info, _trust = self.peers.get(self.resolve_ref(peer))
        return (
            local_view(info.card, local_url) if local_url else copy.deepcopy(info.card)
        )

    def whoami(self) -> Dict[str, Any]:
        return {
            "agent_id": self.identity.agent_id,
            "public_url": self.base_url,
            "org": self.orgs.own_org if self.orgs else None,
        }

    # -- push (ticket #16) ----------------------------------------------------------------
    def rewrite_push_outbound(
        self, rpc: Dict[str, Any], info: CardInfo
    ) -> Dict[str, Any]:
        from .push import rewrite_outbound

        return rewrite_outbound(self, rpc, info)

    def rewrite_push_inbound(
        self, rpc: Dict[str, Any], sender: CardInfo
    ) -> Dict[str, Any]:
        from .push import rewrite_inbound

        return rewrite_inbound(self, rpc, sender)

    def handle_push_delivery(self, req: Request, ref: str) -> Response:
        from .push import handle_delivery

        return handle_delivery(self, req, ref)

    def handle_intake(self, req: Request) -> Response:
        from .push import handle_intake

        return handle_intake(self, req)


def run_forever(cfg: Dict[str, Any]) -> None:
    sc = Sidecar(cfg).start()
    print("READY " + json.dumps(sc.ready_info()), flush=True)
    stop = threading.Event()
    try:
        while not stop.wait(3600):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        sc.stop()
