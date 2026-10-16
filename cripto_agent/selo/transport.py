"""Transporte de referencia sobre HTTP(S). A seguranca vem do envelope, nao do canal.

TLS e opcional e recomendado (oculta metadados de roteamento: remetente, destinatario, epoca,
tamanho). Em qualquer caso o servidor nunca expoe o motivo exato de uma rejeicao a quem
nao autenticou (resposta generica 400), para nao criar oraculos.
"""

from __future__ import annotations

import http.client
import json
import logging
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Set
from urllib.parse import parse_qs, urlsplit

from .agent import Agent
from .envelope import MAX_ENVELOPE
from .keys import OrgParams, verify_doc
from .org import Organization
from .util import SeloError

LOG = logging.getLogger(__name__)


def _make_handler(routes_post: Dict[str, Callable[[Any], Any]],
                  routes_get: Dict[str, Callable[[Dict[str, list]], Any]]):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            self.request.settimeout(10)
            super().setup()

        def log_message(self, *_: Any) -> None:           # nao registrar conteudo controlado por cliente
            pass

        def _reply(self, status: int, payload: Any) -> None:
            data = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            fn = routes_get.get(url.path)
            try:
                if fn is None:
                    return self._reply(404, {"error": "not_found"})
                result = fn(parse_qs(url.query))
                self._reply(200 if result is not None else 404, result if result is not None
                            else {"error": "not_found"})
            except SeloError:
                self._reply(400, {"error": "rejected"})
            except Exception:
                LOG.error("get_failed")
                self._reply(500, {"error": "internal"})

        def do_POST(self) -> None:
            fn = routes_post.get(urlsplit(self.path).path)
            try:
                if fn is None:
                    return self._reply(404, {"error": "not_found"})
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                    return self._reply(400, {"error": "rejected"})
                size = int(lengths[0])
                if not 0 < size <= MAX_ENVELOPE + 4096:
                    return self._reply(413, {"error": "too_large"})
                raw = self.rfile.read(size)
                self._reply(200, fn(json.loads(raw)))
            except (SeloError, ValueError, UnicodeError) as error:
                LOG.info("rejected code=%s", getattr(error, "code", "parse"))
                self._reply(400, {"error": "rejected"})
            except Exception:
                LOG.error("post_failed")
                self._reply(500, {"error": "internal"})

    return Handler


class _Server:
    def __init__(self, handler, host: str, port: int, ssl_context: Optional[ssl.SSLContext]):
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.scheme = "http"
        if ssl_context is not None:
            self.httpd.socket = ssl_context.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.host = host
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.httpd.server_port}"

    def start(self) -> "_Server":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def serve_agent(agent: Agent, host: str = "127.0.0.1", port: int = 0,
                ssl_context: Optional[ssl.SSLContext] = None) -> _Server:
    handler = _make_handler(
        {"/selo/v1/inbox": agent.handle},
        {"/selo/v1/catalog": lambda _q: agent.catalog()})
    return _Server(handler, host, port, ssl_context).start()


def serve_org(org: Organization, host: str = "127.0.0.1", port: int = 0,
              ssl_context: Optional[ssl.SSLContext] = None) -> _Server:
    """Servico publico de diretorio da organizacao (somente dados publicos e assinados)."""
    def entry(q):
        return org.epoch_entry(q["id"][0], int(q["epoch"][0]) if "epoch" in q else None)

    def manifest(q):
        return org.manifest_bundle(q["h"][0])

    handler = _make_handler({}, {
        "/org/v1/params": lambda _q: org.params.to_dict(),
        "/org/v1/entry": entry,
        "/org/v1/manifest": manifest,
        "/org/v1/sth": lambda _q: org.sth(),
        "/org/v1/revoked": lambda _q: org.revocation_list()})
    return _Server(handler, host, port, ssl_context).start()


# ------------------------------------------------------------------ cliente
def _request(url: str, method: str, body: Any = None, timeout: float = 10,
             ssl_context: Optional[ssl.SSLContext] = None) -> Any:
    target = urlsplit(url)
    if target.scheme not in ("http", "https") or not target.hostname:
        raise SeloError("bad_url")
    cls = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    kwargs = {"context": ssl_context} if target.scheme == "https" else {}
    conn = cls(target.hostname, target.port or (443 if target.scheme == "https" else 80),
               timeout=timeout, **kwargs)
    try:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        conn.request(method, target.path + (f"?{target.query}" if target.query else ""), data,
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(MAX_ENVELOPE * 4 + 1)
        if len(raw) > MAX_ENVELOPE * 4:
            raise SeloError("response_too_large")
        if response.status != 200:
            raise SeloError("transport_error", str(response.status))
        return json.loads(raw)
    finally:
        conn.close()


def http_send(entry: Dict[str, Any], envelope: Dict[str, Any],
              ssl_context: Optional[ssl.SSLContext] = None) -> Dict[str, Any]:
    """`send` para Agent.call: o endereco vem da entrada de diretorio assinada pela organizacao."""
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        raise SeloError("no_url")
    return _request(url.rstrip("/") + "/selo/v1/inbox", "POST", envelope, ssl_context=ssl_context)


def fetch_catalog(url: str, ssl_context: Optional[ssl.SSLContext] = None) -> Any:
    return _request(url.rstrip("/") + "/selo/v1/catalog", "GET", ssl_context=ssl_context)


class OrgClient:
    """Cliente do servico de diretorio da organizacao (verifica tudo contra a ancora de confianca)."""

    def __init__(self, url: str, params: OrgParams, ssl_context: Optional[ssl.SSLContext] = None):
        self.url, self.params, self.ssl = url.rstrip("/"), params, ssl_context

    @staticmethod
    def bootstrap_params(url: str, ssl_context: Optional[ssl.SSLContext] = None) -> OrgParams:
        """Ancora de confianca: deve ser conferida fora de banda (hash da chave publica)."""
        return OrgParams.from_dict(_request(url.rstrip("/") + "/org/v1/params", "GET",
                                            ssl_context=ssl_context))

    def directory(self, agent_id: str, epoch: int) -> Dict[str, Any]:
        return _request(f"{self.url}/org/v1/entry?id={agent_id}&epoch={epoch}", "GET",
                        ssl_context=self.ssl)

    def entry(self, agent_id: str) -> Dict[str, Any]:
        return _request(f"{self.url}/org/v1/entry?id={agent_id}", "GET", ssl_context=self.ssl)

    def manifest_bundle(self, h: str) -> Any:
        try:
            return _request(f"{self.url}/org/v1/manifest?h={h}", "GET", ssl_context=self.ssl)
        except SeloError:
            return None

    def revoked(self) -> Set[int]:
        doc = _request(f"{self.url}/org/v1/revoked", "GET", ssl_context=self.ssl)
        return set(verify_doc(self.params.sig_pub, "selo/revoked", doc)["serials"])
