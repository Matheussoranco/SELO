"""Harness do seam principal: processos separados, proxy de rede com falhas e relogio injetavel.

Tres pecas, usadas por todos os testes de ponta a ponta:

* ``Proc`` sobe um processo Python e espera a linha ``READY <json>`` no stdout. O JSON traz
  o que o teste precisa saber (portas, URLs, ids). Os testes nunca importam o codigo do
  processo filho: falam com ele pela rede, como um par real.
* ``TapProxy`` e um proxy HTTP reverso posto entre dois sidecars (o Agent Card do alvo
  anuncia a URL do proxy). Ele registra cada troca e permite injetar falhas:
  ``tamper_next`` (inverte um byte do proximo corpo), ``drop_next`` (descarta),
  ``replay`` (reenvia uma requisicao antiga, o que tambem cobre reordenacao: uma mensagem
  velha entregue depois de mensagens novas) e ``plaintext_seen`` (procura texto em claro).
  Respostas em streaming (SSE) sao repassadas pedaco a pedaco.
* Relogio: processos aceitam ``clock_offset`` (segundos) na configuracao; testes em
  processo usam ``FakeClock``. Assim se simula relogio dessincronizado e validade vencida
  sem esperar o tempo passar.
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


class FakeClock:
    """Relogio controlado pelo teste. Chamavel, como ``time.time``."""

    def __init__(self, start: Optional[float] = None) -> None:
        self.t = float(start if start is not None else time.time())

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Proc:
    """Processo filho que anuncia prontidao com ``READY <json>`` no stdout."""

    def __init__(
        self,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        ready_timeout: float = 30.0,
        cwd: Optional[Path] = None,
    ) -> None:
        full_env = dict(os.environ)
        full_env["PYTHONPATH"] = os.pathsep.join(
            [str(ROOT)]
            + ([full_env["PYTHONPATH"]] if full_env.get("PYTHONPATH") else [])
        )
        full_env["PYTHONUNBUFFERED"] = "1"
        full_env.update(env or {})
        self.args = args
        self.p = subprocess.Popen(
            [PYTHON, *args],
            cwd=str(cwd or ROOT),
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.out: List[str] = []
        self.err: List[str] = []
        self.info: Dict = {}
        ready = threading.Event()

        def pump_out() -> None:
            assert self.p.stdout is not None
            for line in self.p.stdout:
                self.out.append(line)
                if line.startswith("READY ") and not ready.is_set():
                    self.info = json.loads(line[6:])
                    ready.set()

        def pump_err() -> None:
            assert self.p.stderr is not None
            for line in self.p.stderr:
                self.err.append(line)

        threading.Thread(target=pump_out, daemon=True).start()
        threading.Thread(target=pump_err, daemon=True).start()
        deadline = time.time() + ready_timeout
        while not ready.wait(0.05):
            if self.p.poll() is not None or time.time() > deadline:
                time.sleep(0.2)
                self.stop()
                raise RuntimeError(
                    f"processo nao ficou pronto: {args}\n"
                    f"stdout:\n{''.join(self.out)}\nstderr:\n{''.join(self.err)}"
                )

    def alive(self) -> bool:
        return self.p.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(timeout)
        for stream in (self.p.stdout, self.p.stderr):
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass

    def logs(self) -> str:
        return "".join(self.out) + "".join(self.err)


@dataclass
class Exchange:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes
    status: int = 0
    response: bytes = b""
    resp_headers: Dict[str, str] = field(default_factory=dict)


_HOP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "host",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
}


class TapProxy:
    """Proxy HTTP reverso com gravacao e injecao de falhas (ver docstring do modulo)."""

    def __init__(self, target: str) -> None:
        self.target = urllib.parse.urlsplit(target)
        if self.target.scheme != "http":
            raise ValueError(
                "o TapProxy so intermedeia HTTP sem TLS (loopback de teste)"
            )
        self.exchanges: List[Exchange] = []
        self._lock = threading.Lock()
        self._mutators: List[Callable[[Exchange], Optional[bytes]]] = []
        self._sse_mutators: List[Callable[[int, bytes], List[bytes]]] = []
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a) -> None:
                pass

            def _handle(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                ex = Exchange(self.command, self.path, dict(self.headers.items()), body)
                with proxy._lock:
                    proxy.exchanges.append(ex)
                    mutator = proxy._mutators.pop(0) if proxy._mutators else None
                if mutator is not None:
                    new_body = mutator(ex)
                    if new_body is None:  # descartar: fecha a conexao sem resposta
                        self.close_connection = True
                        ex.status = -1
                        return
                    body = new_body
                proxy._forward(self, ex, body)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _forward(
        self, handler: BaseHTTPRequestHandler, ex: Exchange, body: bytes
    ) -> None:
        conn = http.client.HTTPConnection(
            self.target.hostname, self.target.port, timeout=60
        )
        headers = {k: v for k, v in ex.headers.items() if k.lower() not in _HOP}
        headers["Content-Length"] = str(len(body))
        headers["Host"] = f"{self.target.hostname}:{self.target.port}"
        try:
            conn.request(ex.method, ex.path, body=body, headers=headers)
            resp = conn.getresponse()
        except OSError:
            handler.send_error(502)
            return
        ex.status = resp.status
        ex.resp_headers = dict(resp.getheaders())
        streaming = "text/event-stream" in (resp.getheader("Content-Type") or "")
        handler.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in _HOP:
                handler.send_header(k, v)
        if streaming:
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.close_connection = True
            chunks = []
            with self._lock:
                sse_mut = self._sse_mutators.pop(0) if self._sse_mutators else None
            if sse_mut is None:
                while True:
                    try:
                        chunk = resp.read1(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    try:
                        handler.wfile.write(chunk)
                        handler.wfile.flush()
                    except OSError:
                        break
            else:
                # repassa evento a evento, aplicando o mutador (indice, evento) -> [eventos]
                buf, idx = b"", 0
                while True:
                    try:
                        chunk = resp.read1(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n\n" in buf:
                        event, buf = buf.split(b"\n\n", 1)
                        out = sse_mut(idx, event + b"\n\n")
                        idx += 1
                        for o in out:
                            chunks.append(o)
                            try:
                                handler.wfile.write(o)
                                handler.wfile.flush()
                            except OSError:
                                pass
            ex.response = b"".join(chunks)
        else:
            data = resp.read()
            ex.response = data
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)
        conn.close()

    # -- injecao de falhas -------------------------------------------------------------------
    def tamper_next(self, position: Optional[int] = None) -> None:
        """Inverte um bit de um byte do proximo corpo de requisicao (meio do corpo por padrao).

        O byte escolhido fica dentro de um valor JSON em base64 sempre que possivel, para que a
        mensagem continue sendo JSON valido e a falha seja detectada pela criptografia.
        """

        def mutate(ex: Exchange) -> bytes:
            b = bytearray(ex.body)
            if not b:
                return bytes(b)
            i = position if position is not None else _b64_byte_index(b)
            b[i] = _flip_b64(b[i])
            return bytes(b)

        self._mutators.append(mutate)

    def mutate_next_stream(self, fn: Callable[[int, bytes], List[bytes]]) -> None:
        """Aplica `fn(indice, evento)` a cada evento SSE da proxima resposta em streaming.

        `fn` devolve a lista de eventos a repassar: [] descarta, [e, e] duplica, e um evento
        guardado e devolvido depois reordena."""
        self._sse_mutators.append(fn)

    def drop_next(self) -> None:
        self._mutators.append(lambda ex: None)

    def replay(self, exchange: Exchange) -> Tuple[int, bytes]:
        """Reenvia ao alvo, sem passar pelos mutadores, uma requisicao gravada."""
        conn = http.client.HTTPConnection(
            self.target.hostname, self.target.port, timeout=30
        )
        headers = {k: v for k, v in exchange.headers.items() if k.lower() not in _HOP}
        headers["Content-Length"] = str(len(exchange.body))
        conn.request(
            exchange.method, exchange.path, body=exchange.body, headers=headers
        )
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def find(self, path_prefix: str) -> List[Exchange]:
        with self._lock:
            return [e for e in self.exchanges if e.path.startswith(path_prefix)]

    def plaintext_seen(self, needle: str) -> bool:
        raw = needle.encode()
        with self._lock:
            return any(raw in e.body or raw in e.response for e in self.exchanges)

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64_byte_index(b: bytearray) -> int:
    """Indice de um caractere base64url no maior valor de string do corpo (fallback: meio)."""
    best, start, i = (len(b) // 2, 0), None, 0
    longest = 0
    while i < len(b):
        if b[i] == 0x22:  # aspas
            if start is None:
                start = i + 1
            else:
                if i - start > longest and all(c in _B64 for c in b[start:i]):
                    longest, best = i - start, (start + (i - start) // 2, 0)
                start = None
        i += 1
    return best[0]


def _flip_b64(c: int) -> int:
    if c in _B64:
        j = _B64.index(c)
        return _B64[(j + 1) % 64]
    return c ^ 0x01


class TcpTap:
    """Encaminhador TCP que grava os bytes brutos nos dois sentidos (serve para TLS)."""

    def __init__(
        self, target_host: str, target_port: int, listen_host: str = "127.0.0.1"
    ) -> None:
        import socket

        self.target = (target_host, target_port)
        self.sock = socket.socket()
        self.sock.bind((listen_host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.data = bytearray()
        self._lock = threading.Lock()
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        import socket

        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                u = socket.create_connection(self.target, timeout=30)
            except OSError:
                c.close()
                continue
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, src, dst) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                with self._lock:
                    self.data += chunk
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def seen(self, needle: bytes) -> bool:
        with self._lock:
            return needle in self.data

    def stop(self) -> None:
        self._stop = True
        self.sock.close()
