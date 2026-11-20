"""HTTP do SELO: cliente com as regras de TLS (especificacao, secao 13), servidor e SSE."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .errors import SeloError

MAX_BODY = 256 * 1024 + 4096
TIMEOUT = 30.0


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> urllib.parse.SplitResult:
    """`http://` so para loopback; fora dele, `https://` e obrigatorio."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise SeloError("bad_url", url)
    if u.scheme == "http" and not is_loopback_host(u.hostname):
        raise SeloError("tls_required", f"{url}: TLS e obrigatorio fora do loopback")
    return u


class HttpClient:
    def __init__(self, ca_file: str | None = None, timeout: float = TIMEOUT) -> None:
        self.timeout = timeout
        self.ssl = (
            ssl.create_default_context(cafile=ca_file)
            if ca_file
            else ssl.create_default_context()
        )

    def _conn(
        self, u: urllib.parse.SplitResult, timeout: float | None
    ) -> http.client.HTTPConnection:
        t = timeout or self.timeout
        if u.scheme == "https":
            return http.client.HTTPSConnection(
                u.hostname, u.port or 443, timeout=t, context=self.ssl
            )
        return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=t)

    def _prepare_request(
        self, method: str, url: str, body: Any = None, headers: dict[str, str] | None = None
    ) -> tuple[http.client.HTTPConnection, str, bytes, dict[str, str]]:
        u = check_url(url)
        data = (
            body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        )
        conn = self._conn(u, None)  # timeout handled by caller
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        return conn, path, data, hdrs

    def request(
        self,
        method: str,
        url: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn, path, data, hdrs = self._prepare_request(method, url, body, headers)
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read(MAX_BODY + 1)
        except ssl.SSLError as e:
            raise SeloError("tls_error", str(e)) from None
        except (OSError, http.client.HTTPException) as e:
            raise SeloError("unreachable", f"{url}: {e}") from None
        finally:
            conn.close()
        if len(raw) > MAX_BODY:
            raise SeloError("body_too_large")
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw

    def json(
        self,
        method: str,
        url: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, Any]:
        status, _h, raw = self.request(method, url, body, headers, timeout)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            raise SeloError(
                "bad_response", f"{url}: resposta nao e JSON (HTTP {status})"
            ) from None

    def stream(
        self,
        method: str,
        url: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> StreamResponse:
        """Abre uma requisicao cuja resposta pode ser SSE. O chamador fecha com `close()`."""
        conn, path, data, hdrs = self._prepare_request(method, url, body, headers)
        hdrs["Accept"] = "text/event-stream, application/json"
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
        except ssl.SSLError as e:
            conn.close()
            raise SeloError("tls_error", str(e)) from None
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise SeloError("unreachable", f"{url}: {e}") from None
        return StreamResponse(conn, resp)


class StreamResponse:
    def __init__(
        self, conn: http.client.HTTPConnection, resp: http.client.HTTPResponse
    ) -> None:
        self.conn, self.resp = conn, resp
        self.status = resp.status
        self.headers = {k.lower(): v for k, v in resp.getheaders()}

    @property
    def is_sse(self) -> bool:
        return "text/event-stream" in self.headers.get("content-type", "")

    def read_all(self) -> bytes:
        try:
            raw = self.resp.read(MAX_BODY + 1)
        finally:
            self.close()
        if len(raw) > MAX_BODY:
            raise SeloError("body_too_large")
        return raw

    def events(self) -> Iterator[str]:
        """Itera os campos `data:` de cada evento SSE (concatenados por linha)."""
        data: list = []
        try:
            while True:
                line = self.resp.readline(MAX_BODY)
                if not line:
                    break
                line = line.rstrip(b"\r\n")
                if not line:
                    if data:
                        yield "\n".join(data)
                        data = []
                    continue
                if line.startswith(b":"):
                    continue
                field, _, value = line.partition(b":")
                if value.startswith(b" "):
                    value = value[1:]
                if field == b"data":
                    data.append(value.decode("utf-8"))
            if data:
                yield "\n".join(data)
        except (OSError, http.client.HTTPException):
            return
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001, S110
            pass


# -- servidor -----------------------------------------------------------------------------
@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes
    client: str

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            raise SeloError("bad_request", "corpo nao e JSON") from None


class Response:
    def __init__(
        self,
        status: int = 200,
        body: Any = None,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
        stream: Iterator[bytes] | None = None,
    ) -> None:
        self.status, self.content_type, self.headers, self.stream = (
            status,
            content_type,
            headers or {},
            stream,
        )
        if body is None:
            self.body = b""
        elif isinstance(body, bytes):
            self.body = body
        else:
            self.body = json.dumps(body, separators=(",", ":")).encode()


def sse_event(data: str) -> bytes:
    return (
        b"".join(b"data: " + line.encode("utf-8") + b"\n" for line in data.split("\n"))
        + b"\n"
    )


Handler = Callable[[Request], Response]


class HttpServer:
    """Servidor HTTP com threads; TLS quando `ssl_context` e dado."""

    def __init__(
        self,
        host: str,
        port: int,
        handler: Handler,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.handler = handler
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "selo"
            sys_version = ""

            def log_message(self, *_a: Any) -> None:
                pass

            def _run(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    self.close_connection = True
                    self._send(Response(413, {"error": "body_too_large"}))
                    return
                body = self.rfile.read(n) if n else b""
                u = urllib.parse.urlsplit(self.path)
                req = Request(
                    self.command,
                    u.path,
                    dict(urllib.parse.parse_qsl(u.query)),
                    {k.lower(): v for k, v in self.headers.items()},
                    body,
                    self.client_address[0],
                )
                try:
                    resp = outer.handler(req)
                except SeloError as e:
                    resp = Response(400, {"error": e.code})
                except Exception as e:  # noqa: BLE001 - nunca vaza detalhes internos
                    import traceback

                    traceback.print_exc()
                    resp = Response(
                        500, {"error": "internal", "type": type(e).__name__}
                    )
                self._send(resp)

            def _send(self, resp: Response) -> None:
                try:
                    self.send_response(resp.status)
                    self.send_header("Content-Type", resp.content_type)
                    for k, v in resp.headers.items():
                        self.send_header(k, v)
                    if resp.stream is not None:
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                        for chunk in resp.stream:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    else:
                        self.send_header("Content-Length", str(len(resp.body)))
                        self.end_headers()
                        self.wfile.write(resp.body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
                    self.close_connection = True
                finally:
                    if resp.stream is not None and hasattr(resp.stream, "close"):
                        try:
                            resp.stream.close()
                        except Exception:  # noqa: BLE001, S110
                            pass

            do_GET = do_POST = do_PUT = do_DELETE = _run

        family = socket.AF_INET6 if ":" in host.strip("[]") else socket.AF_INET

        class Srv(ThreadingHTTPServer):
            address_family = family
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = Srv((host.strip("[]"), port), H)
        if ssl_context is not None:
            self.httpd.socket = ssl_context.wrap_socket(
                self.httpd.socket, server_side=True
            )
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> HttpServer:
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, args=(0.05,), daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
