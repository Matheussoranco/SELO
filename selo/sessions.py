"""Sessoes: handshake Noise IK + Double Ratchet sobre HTTP (especificacao, secao 9).

Regras de canal (9.6): metodo nao streaming sem sessao vai por envelope e, em seguida, o
sidecar abre uma sessao para as proximas chamadas; com sessao, vai pela sessao; streaming
exige sessao. Sessao perdida (`unknown_session`) -> recuo para envelope, ou novo
handshake no caso de streaming (9.5). O estado do ratchet e persistido apos cada operacao.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional

from . import PROTOCOL, channel, jcs
from .card import CLOCK_SKEW, CardInfo
from .crypto.noise import HandshakeState
from .crypto.primitives import b64u, unb64u
from .crypto.ratchet import Ratchet, root_from_handshake, seal_with
from .errors import SeloError
from .escrow import capsule_digest, check_capsule_shape, make_capsule
from .net import Request, Response, sse_event
from .peers import PeerTrust

SESSION_PATH = "/selo/v1/session"
MSG_FIELDS = {"sid", "hdr", "ct"}


@dataclass
class Session:
    sid: str
    peer_id: str
    peer_url: str
    role: str  # "i" (iniciador) ou "r" (respondedor)
    exp: int
    ratchet: Ratchet
    peer_seq: int
    my_seq: int
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @property
    def send_dir(self) -> str:
        return "i2r" if self.role == "i" else "r2i"

    @property
    def recv_dir(self) -> str:
        return "r2i" if self.role == "i" else "i2r"


def prologue(responder: str, responder_seq: int) -> bytes:
    return b"selo/1/session\x00" + jcs.canonicalize(
        {"responder": responder, "responder_seq": responder_seq}
    )


def _ad_base(sid: str, direction: str, hdr: Dict[str, Any]) -> bytes:
    return jcs.canonicalize({"sid": sid, "dir": direction}) + jcs.canonicalize(hdr)


class SessionManager:
    def __init__(self, sidecar: Any) -> None:
        self.sc = sidecar
        self._live: Dict[str, Session] = {}
        self._lock = threading.Lock()
        self._hs_locks: Dict[str, threading.Lock] = {}

    # -- persistencia ---------------------------------------------------------------------
    def _save(self, s: Session) -> None:
        self.sc.store.save_session(
            s.sid,
            s.peer_id,
            s.peer_url,
            s.role,
            s.exp,
            {
                "ratchet": s.ratchet.to_dict(),
                "peer_seq": s.peer_seq,
                "my_seq": s.my_seq,
            },
        )

    def _load(self, sid: str) -> Optional[Session]:
        with self._lock:
            s = self._live.get(sid)
            if s is not None:
                return s
            row = self.sc.store.load_session(sid)
            if row is None:
                return None
            peer_id, peer_url, role, exp, data = row
            s = Session(
                sid,
                peer_id,
                peer_url,
                role,
                exp,
                Ratchet.from_dict(data["ratchet"]),
                data["peer_seq"],
                data["my_seq"],
            )
            self._live[sid] = s
            return s

    def _drop(self, sid: str) -> None:
        with self._lock:
            self._live.pop(sid, None)
        self.sc.store.delete_session(sid)

    # -- mensagens de sessao --------------------------------------------------------------
    def seal(
        self, s: Session, payload: Dict[str, Any], trust: PeerTrust
    ) -> Dict[str, Any]:
        with s.lock:
            hdr, mk = s.ratchet.next_send()
            base = _ad_base(s.sid, s.send_dir, hdr)
            target = self.sc.escrow_target(trust)
            capsule = make_capsule(target, base, mk) if target else None
            ct = seal_with(
                mk, base + capsule_digest(capsule), jcs.canonicalize(payload)
            )
            self._save(s)
        msg: Dict[str, Any] = {"sid": s.sid, "hdr": hdr, "ct": b64u(ct)}
        if capsule is not None:
            msg["escrow"] = capsule
        return msg

    def open(self, s: Session, msg: Any, trust: PeerTrust) -> Dict[str, Any]:
        if not isinstance(msg, dict) or not (
            MSG_FIELDS <= set(msg) <= MSG_FIELDS | {"escrow"}
        ):
            raise SeloError("bad_message", "forma da mensagem de sessao")
        if msg["sid"] != s.sid or not isinstance(msg["ct"], str):
            raise SeloError("bad_message", "sid")
        capsule = msg.get("escrow")
        org = self.sc.escrow_org_for(trust)
        if org is not None:
            check_capsule_shape(capsule, org)
        elif capsule is not None:
            raise SeloError("bad_message", "capsula de escrow inesperada")
        hdr = msg["hdr"]
        try:
            base = _ad_base(s.sid, s.recv_dir, hdr)
        except SeloError:
            raise SeloError("bad_header") from None
        with s.lock:
            pt, _mk = s.ratchet.decrypt(
                hdr, base + capsule_digest(capsule), unb64u(msg["ct"])
            )
            self._save(s)
        try:
            payload = json.loads(pt)
        except ValueError:
            raise SeloError("bad_payload") from None
        if not isinstance(payload, dict):
            raise SeloError("bad_payload")
        return payload

    # -- iniciador ------------------------------------------------------------------------
    def handshake(self, info: CardInfo) -> Session:
        sc = self.sc
        now = sc.clock()
        hs = HandshakeState(
            "IK",
            True,
            prologue(info.agent_id, info.kel.seq),
            s=sc.identity.agree_key,
            rs=info.agree_pub,
        )
        m1 = hs.write_message(
            jcs.canonicalize(
                {
                    "agent_id": sc.identity.agent_id,
                    "card": sc.base_url,
                    "seq": sc.identity.seq,
                    "iat": int(now),
                }
            )
        )
        req = {
            "v": PROTOCOL,
            "responder": info.agent_id,
            "responder_seq": info.kel.seq,
            "m1": b64u(m1),
        }
        sc.capture("out", "handshake", req)
        status, body = sc.http.json("POST", info.base_url + SESSION_PATH, req)
        if status != 200 or not isinstance(body, dict) or "m2" not in body:
            raise SeloError(
                (
                    (body or {}).get("error", "handshake_failed")
                    if isinstance(body, dict)
                    else "handshake_failed"
                ),
                f"HTTP {status}",
            )
        p2 = json.loads(hs.read_message(unb64u(body["m2"])))
        sid, exp = p2.get("sid"), p2.get("exp")
        if not isinstance(sid, str) or type(exp) is not int:
            raise SeloError("handshake_failed", "payload de m2")
        sk = root_from_handshake(hs.ck, hs.h)
        s = Session(
            sid,
            info.agent_id,
            info.base_url,
            "i",
            min(exp, int(now) + int(sc.cfg["session_ttl"])),
            Ratchet.init_alice(sk, hs.re),
            info.kel.seq,
            sc.identity.seq,
        )
        with self._lock:
            self._live[sid] = s
        self._save(s)
        return s

    def _session_for(self, info: CardInfo) -> Optional[Session]:
        sid = self.sc.store.find_initiator_session(info.agent_id, self.sc.clock())
        if sid is None:
            return None
        s = self._load(sid)
        if s is None:
            return None
        if s.my_seq != self.sc.identity.seq or not info.kel.key_usable(
            s.peer_seq, self.sc.clock()
        ):
            self._drop(sid)  # alguma das chaves estaticas girou: nova sessao
            return None
        return s

    def _ensure_session(self, info: CardInfo) -> Session:
        with self._lock:
            lk = self._hs_locks.setdefault(info.agent_id, threading.Lock())
        with lk:
            s = self._session_for(info)
            return s if s is not None else self.handshake(info)

    def _post(
        self, s: Session, info: CardInfo, trust: PeerTrust, rpc: Dict[str, Any]
    ) -> Dict[str, Any]:
        msg = self.seal(s, {"rpc": rpc}, trust)
        self.sc.capture("out", "session", msg)
        status, body = self.sc.http.json(
            "POST", f"{info.base_url}{SESSION_PATH}/{s.sid}", msg
        )
        if status == 404:
            raise SeloError("unknown_session")
        if status != 200 or not isinstance(body, dict) or "error" in body:
            raise SeloError(
                (
                    (body or {}).get("error", "peer_error")
                    if isinstance(body, dict)
                    else "peer_error"
                ),
                f"HTTP {status}",
            )
        self.sc.capture("in", "session", body)
        resp = self.open(s, body, trust).get("rpc")
        if not isinstance(resp, dict):
            raise SeloError("bad_response", "resposta sem rpc")
        return resp

    def call(
            self, info: CardInfo, trust: PeerTrust, rpc: Dict[str, Any]
        ) -> Dict[str, Any]:
            for attempt in (1, 2):
                s = self._session_for(info)
                if channel.choose(rpc["method"], s is not None) == channel.ENVELOPE:
                    resp = self.sc.call_envelope(info, trust, rpc)
                    self._try_open_session(info)
                    return resp
                try:
                    return self._post(s, info, trust, rpc)
                except SeloError as e:
                    if e.code != "unknown_session":
                        raise
                    self._drop(s.sid)
                    if attempt == 1:
                        continue  # recuo: novo handshake ou envelope
                    # Segunda tentativa: recuo para envelope
                    resp = self.sc.call_envelope(info, trust, rpc)
                    self._try_open_session(info)
                    return resp
            # Nao alcancavel: o loop retorna ou levanta
            raise SeloError("peer_error", "call failed after retries")

    def _try_open_session(self, info: CardInfo) -> None:
        try:
            self._ensure_session(info)
        except SeloError:
            pass  # a proxima chamada tenta de novo; o envelope ja funcionou

    def stream(
        self, info: CardInfo, trust: PeerTrust, rpc: Dict[str, Any]
    ) -> Iterator[Dict[str, Any]]:
        for attempt in (1, 2):
            s = self._ensure_session(info)
            msg = self.seal(s, {"rpc": rpc}, trust)
            self.sc.capture("out", "session", msg)
            r = self.sc.http.stream(
                "POST", f"{info.base_url}{SESSION_PATH}/{s.sid}", msg
            )
            if r.status == 404 and attempt == 1:
                r.close()
                self._drop(s.sid)
                continue  # novo handshake e reenvio
            if r.status != 200:
                raw = r.read_all()
                try:
                    code = json.loads(raw).get("error", "peer_error")
                except (ValueError, AttributeError):
                    code = "peer_error"
                raise SeloError(code, f"HTTP {r.status}")
            if not r.is_sse:
                body = json.loads(r.read_all())
                yield self.open(s, body, trust)["rpc"]
                return
            yield from self._read_stream(s, r, trust)
            return

    def _read_stream(
        self, s: Session, r: Any, trust: PeerTrust
    ) -> Iterator[Dict[str, Any]]:
        expected = 0
        try:
            for data in r.events():
                try:
                    msg = json.loads(data)
                except ValueError:
                    raise SeloError("bad_message", "evento nao e JSON") from None
                self.sc.capture("in", "session", msg)
                payload = self.open(s, msg, trust)
                if payload.get("i") != expected:
                    raise SeloError(
                        "stream_out_of_order",
                        f"esperado {expected}, veio {payload.get('i')}",
                    )
                expected += 1
                if payload.get("end") is True:
                    return
                ev = payload.get("event")
                if not isinstance(ev, dict):
                    raise SeloError("bad_payload", "evento sem conteudo")
                yield ev
            raise SeloError("stream_truncated", "o stream terminou sem o marcador end")
        finally:
            r.close()

    # -- respondedor ----------------------------------------------------------------------
    def handle_handshake(self, req: Request) -> Response:
        sc = self.sc
        body = req.json()
        sc.capture("in", "handshake", body)
        if (
            not isinstance(body, dict)
            or body.get("v") != PROTOCOL
            or body.get("responder") != sc.identity.agent_id
            or type(body.get("responder_seq")) is not int
            or not isinstance(body.get("m1"), str)
        ):
            raise SeloError("bad_handshake")
        now = sc.clock()
        my_seq = body["responder_seq"]
        agree = sc.identity.agree_key_for(my_seq, now)
        hs = HandshakeState(
            "IK", False, prologue(sc.identity.agent_id, my_seq), s=agree
        )
        try:
            p1 = json.loads(hs.read_message(unb64u(body["m1"])))
        except ValueError:
            raise SeloError("bad_handshake", "payload de m1") from None
        if (
            not isinstance(p1, dict)
            or set(p1) != {"agent_id", "card", "seq", "iat"}
            or type(p1["seq"]) is not int
            or type(p1["iat"]) is not int
        ):
            raise SeloError("bad_handshake", "payload de m1")
        if abs(now - p1["iat"]) > CLOCK_SKEW:
            raise SeloError("invalid_lifetime", "iat do handshake")
        info, _trust = sc.resolve_peer_at(p1["card"], p1["agent_id"], p1["seq"])
        if (
            not info.kel.key_usable(p1["seq"], now)
            or info.kel.entry(p1["seq"]).agree_pub != hs.rs
        ):
            raise SeloError(
                "identity_mismatch",
                "chave estatica do iniciador nao confere com o Card",
            )
        sid = b64u(os.urandom(16))
        exp = int(now) + int(sc.cfg["session_ttl"])
        m2 = hs.write_message(jcs.canonicalize({"sid": sid, "exp": exp}))
        sk = root_from_handshake(hs.ck, hs.h)
        s = Session(
            sid,
            info.agent_id,
            info.base_url,
            "r",
            exp,
            Ratchet.init_bob(sk, hs.e),
            p1["seq"],
            my_seq,
        )
        with self._lock:
            self._live[sid] = s
        self._save(s)
        out = {"m2": b64u(m2)}
        sc.capture("out", "handshake", out)
        return Response(200, out)

    def handle_message(self, req: Request, sid: str) -> Response:
        sc = self.sc
        now = sc.clock()
        s = self._load(sid)
        if s is None or s.role != "r":
            raise SeloError("unknown_session")
        if now >= s.exp or not sc.identity.state.key_usable(s.my_seq, now):
            self._drop(sid)
            raise SeloError("unknown_session")
        info, trust = sc.resolve_peer_at(s.peer_url, s.peer_id, s.peer_seq)
        if not info.kel.key_usable(s.peer_seq, now):
            self._drop(sid)
            raise SeloError("unknown_session")
        msg = req.json()
        sc.capture("in", "session", msg)
        payload = self.open(s, msg, trust)
        rpc = payload.get("rpc")
        rid = rpc.get("id") if isinstance(rpc, dict) else None
        method = rpc.get("method") if isinstance(rpc, dict) else None
        if isinstance(method, str) and channel.is_streaming(method):
            return Response(
                200,
                content_type="text/event-stream",
                stream=self._stream_out(s, info, trust, rpc),
            )
        try:
            result = sc.dispatch_inbound(rpc, info, trust)
        except SeloError as e:
            result = {"jsonrpc": "2.0", "id": rid, "error": e.jsonrpc_error()}
        out = self.seal(s, {"rpc": result}, trust)
        sc.capture("out", "session", out)
        return Response(200, out)

    def _stream_out(
        self, s: Session, info: CardInfo, trust: PeerTrust, rpc: Dict[str, Any]
    ) -> Iterator[bytes]:
        i = 0
        try:
            for ev in self.sc.stream_inbound(rpc, info, trust):
                msg = self.seal(s, {"i": i, "event": ev}, trust)
                self.sc.capture("out", "session", msg)
                yield sse_event(json.dumps(msg))
                i += 1
        except SeloError as e:
            err = {"jsonrpc": "2.0", "id": rpc.get("id"), "error": e.jsonrpc_error()}
            yield sse_event(json.dumps(self.seal(s, {"i": i, "event": err}, trust)))
            i += 1
        yield sse_event(json.dumps(self.seal(s, {"i": i, "end": True}, trust)))
