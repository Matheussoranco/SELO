"""Canal local agente <-> sidecar (especificacao, secao 12).

* ``pipe`` (Windows) / ``unix`` (POSIX): ``multiprocessing.connection`` com desafio HMAC
  (``authkey`` de 32 bytes em arquivo legivel so pelo usuario) alem da ACL do sistema. Os
  quadros sao JSON (``send_bytes``/``recv_bytes``); nunca pickle.
* ``http``: loopback com ``Authorization: Bearer <token>`` e uma interface compatível com A2A
  por par (``/peers/<R>/``), para clientes A2A comuns.

O arquivo ``<state_dir>/run/local.json`` diz ao agente como se conectar.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import stat
import sys
import threading
import urllib.parse
from multiprocessing.connection import Client, Listener
from typing import Any, Callable, Dict, Iterator, Optional

from .card import WELL_KNOWN
from .errors import SeloError
from .net import HttpClient, HttpServer, Request, Response, sse_event

MAX_FRAME = 1024 * 1024


class LocalApi:
    """O que o sidecar oferece ao agente. Implementado por `selo.sidecar.Sidecar`."""

    def call(self, peer: str, rpc: Dict[str, Any]) -> Dict[str, Any]: ...
    def stream(self, peer: str, rpc: Dict[str, Any]) -> Iterator[Dict[str, Any]]: ...
    def peer_card(self, peer: str, local_url: Optional[str]) -> Dict[str, Any]: ...
    def whoami(self) -> Dict[str, Any]: ...


def _private_file(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def default_mode() -> str:
    return "pipe" if sys.platform == "win32" else "unix"


def _frames_error(e: SeloError) -> Dict[str, Any]:
    return {"error": e.jsonrpc_error()}


class LocalServer:
    def __init__(
        self,
        api: LocalApi,
        state_dir: str,
        name: str,
        mode: str = "auto",
        port: int = 0,
    ) -> None:
        self.api, self.state_dir, self.name = api, state_dir, name
        self.mode = default_mode() if mode == "auto" else mode
        self.port = port
        self.run_dir = os.path.join(state_dir, "run")
        self.info: Dict[str, Any] = {}
        self._listener: Optional[Listener] = None
        self._http: Optional[HttpServer] = None
        self._stopped = threading.Event()

    # -- ciclo de vida --------------------------------------------------------------------
    def start(self) -> "LocalServer":
        os.makedirs(self.run_dir, exist_ok=True)
        if self.mode in ("pipe", "unix"):
            key = secrets.token_bytes(32)
            key_file = os.path.join(self.run_dir, "local.key")
            _private_file(key_file, key)
            if self.mode == "pipe":
                if sys.platform != "win32":
                    raise SeloError("bad_config", "named pipe so no Windows")
                address = rf"\\.\pipe\selo-{self.name}-{secrets.token_hex(8)}"
                self._listener = Listener(address, family="AF_PIPE", authkey=key)
            else:
                if not hasattr(__import__("socket"), "AF_UNIX"):
                    raise SeloError(
                        "bad_config", "socket Unix indisponivel nesta plataforma"
                    )
                os.chmod(self.run_dir, stat.S_IRWXU)
                address = os.path.join(self.run_dir, "local.sock")
                if os.path.exists(address):
                    os.unlink(address)
                self._listener = Listener(address, family="AF_UNIX", authkey=key)
                os.chmod(address, stat.S_IRUSR | stat.S_IWUSR)
            self.info = {"mode": self.mode, "address": address, "key_file": key_file}
            threading.Thread(target=self._accept_loop, daemon=True).start()
        elif self.mode == "http":
            token = secrets.token_urlsafe(32)
            token_file = os.path.join(self.run_dir, "local.token")
            _private_file(token_file, token.encode())
            self._token = token
            self._http = HttpServer("127.0.0.1", self.port, self._handle_http).start()
            self.info = {
                "mode": "http",
                "url": f"http://127.0.0.1:{self._http.port}",
                "token_file": token_file,
            }
        else:
            raise SeloError("bad_config", f"modo local desconhecido: {self.mode}")
        _private_file(
            os.path.join(self.run_dir, "local.json"), json.dumps(self.info).encode()
        )
        return self

    def stop(self) -> None:
        self._stopped.set()
        if self._http:
            self._http.stop()
        if self._listener is not None:
            try:
                self._listener.close()
            except Exception:
                pass

    # -- pipe / unix ----------------------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stopped.is_set():
            try:
                conn = self._listener.accept()  # faz o desafio HMAC
            except Exception:
                if self._stopped.is_set():
                    return
                continue  # cliente sem a chave: ignorado
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: Any) -> None:
        try:
            while True:
                try:
                    raw = conn.recv_bytes(MAX_FRAME)
                except (EOFError, OSError):
                    return
                try:
                    frame = json.loads(raw)
                    if not isinstance(frame, dict):
                        raise SeloError("bad_request", "quadro nao e objeto")
                    op = frame.get("op")
                    if op == "call":
                        conn.send_bytes(
                            json.dumps(
                                {"rpc": self.api.call(frame["peer"], frame["rpc"])}
                            ).encode()
                        )
                    elif op == "stream":
                        for ev in self.api.stream(frame["peer"], frame["rpc"]):
                            conn.send_bytes(json.dumps({"event": ev}).encode())
                        conn.send_bytes(b'{"end": true}')
                    elif op == "card":
                        conn.send_bytes(
                            json.dumps(
                                {"card": self.api.peer_card(frame["peer"], None)}
                            ).encode()
                        )
                    elif op == "whoami":
                        conn.send_bytes(
                            json.dumps({"whoami": self.api.whoami()}).encode()
                        )
                    else:
                        raise SeloError("bad_request", f"op desconhecida: {op!r}")
                except SeloError as e:
                    conn.send_bytes(json.dumps(_frames_error(e)).encode())
                except (KeyError, ValueError, TypeError):
                    conn.send_bytes(
                        json.dumps(_frames_error(SeloError("bad_request"))).encode()
                    )
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # -- http -----------------------------------------------------------------------------
    def _authorized(self, req: Request) -> bool:
        got = req.headers.get("authorization", "")
        return hmac.compare_digest(got.encode(), f"Bearer {self._token}".encode())

    def _handle_http(self, req: Request) -> Response:
        if not self._authorized(req):
            return Response(401, {"error": "unauthorized"})
        parts = req.path.split("/")
        if req.method == "GET" and req.path == "/whoami":
            return Response(200, self.api.whoami())
        if len(parts) >= 3 and parts[1] == "peers":
            peer = urllib.parse.unquote(parts[2])
            rest = "/" + "/".join(parts[3:])
            local_url = f"{self.info['url']}/peers/{parts[2]}"
            if req.method == "GET" and rest == WELL_KNOWN:
                try:
                    return Response(200, self.api.peer_card(peer, local_url))
                except SeloError as e:
                    return Response(502, {"error": e.code})
            if req.method == "POST" and rest in ("/", ""):
                try:
                    rpc = req.json()
                except SeloError:
                    return Response(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32700, "message": "parse error"},
                        },
                    )
                from .channel import is_streaming

                if isinstance(rpc, dict) and is_streaming(str(rpc.get("method"))):
                    events = self.api.stream(peer, rpc)
                    return Response(
                        200,
                        content_type="text/event-stream",
                        stream=(sse_event(json.dumps(ev)) for ev in events),
                    )
                return Response(200, self.api.call(peer, rpc))
        return Response(404, {"error": "not_found"})


class LocalClient:
    """Cliente do canal local, usado pelo agente (ou por testes)."""

    def __init__(
        self, state_dir: Optional[str] = None, info: Optional[Dict[str, Any]] = None
    ) -> None:
        if info is None:
            with open(
                os.path.join(state_dir or ".", "run", "local.json"), encoding="utf-8"
            ) as fh:
                info = json.load(fh)
        self.info = info
        self.mode = info["mode"]
        if self.mode in ("pipe", "unix"):
            with open(info["key_file"], "rb") as fh:
                self._key = fh.read()
        else:
            with open(info["token_file"], "rb") as fh:
                self._token = fh.read().decode()
            self._http = HttpClient()

    def _conn(self) -> Any:
        family = "AF_PIPE" if self.mode == "pipe" else "AF_UNIX"
        return Client(self.info["address"], family=family, authkey=self._key)

    def _roundtrip(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        conn = self._conn()
        try:
            conn.send_bytes(json.dumps(frame).encode())
            return json.loads(conn.recv_bytes(MAX_FRAME))
        finally:
            conn.close()

    @staticmethod
    def _check(reply: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in reply:
            err = reply["error"]
            raise SeloError(err.get("message", "error"), str(err.get("data", "")))
        return reply

    def call(self, peer: str, rpc: Dict[str, Any]) -> Dict[str, Any]:
        if self.mode == "http":
            status, body = self._http.json(
                "POST",
                f"{self.info['url']}/peers/{urllib.parse.quote(peer, safe='')}/",
                rpc,
                {"Authorization": f"Bearer {self._token}"},
            )
            if status != 200:
                raise SeloError((body or {}).get("error", "local_error"))
            return body
        return self._check(self._roundtrip({"op": "call", "peer": peer, "rpc": rpc}))[
            "rpc"
        ]

    def stream(self, peer: str, rpc: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        if self.mode == "http":
            r = self._http.stream(
                "POST",
                f"{self.info['url']}/peers/{urllib.parse.quote(peer, safe='')}/",
                rpc,
                {"Authorization": f"Bearer {self._token}"},
            )
            if not r.is_sse:
                body = json.loads(r.read_all() or b"null")
                yield body
                return
            for data in r.events():
                yield json.loads(data)
            return
        conn = self._conn()
        try:
            conn.send_bytes(
                json.dumps({"op": "stream", "peer": peer, "rpc": rpc}).encode()
            )
            while True:
                reply = self._check(json.loads(conn.recv_bytes(MAX_FRAME)))
                if reply.get("end"):
                    return
                yield reply["event"]
        finally:
            conn.close()

    def card(self, peer: str) -> Dict[str, Any]:
        if self.mode == "http":
            status, body = self._http.json(
                "GET",
                f"{self.info['url']}/peers/{urllib.parse.quote(peer, safe='')}{WELL_KNOWN}",
                None,
                {"Authorization": f"Bearer {self._token}"},
            )
            if status != 200:
                raise SeloError((body or {}).get("error", "local_error"))
            return body
        return self._check(self._roundtrip({"op": "card", "peer": peer}))["card"]

    def whoami(self) -> Dict[str, Any]:
        if self.mode == "http":
            return self._http.json(
                "GET",
                f"{self.info['url']}/whoami",
                None,
                {"Authorization": f"Bearer {self._token}"},
            )[1]
        return self._check(self._roundtrip({"op": "whoami"}))["whoami"]


Callback = Callable[..., Any]
