"""Laboratorio de 3 nos: agente A -> [no do meio, tipo tcpdump/MITM] -> agente B, em sockets TCP reais.

Mostra (1) o que um observador passivo enxerga, (2) o que acontece se o no do meio ALTERA 1 byte e
(3) se ele REENVIA a requisicao. Roda em loopback; para maquinas diferentes, troque 127.0.0.1 pelos
IPs e rode a organizacao, os agentes e o no do meio em hosts distintos (o no do meio pode ser um
tcpdump/Wireshark em vez deste proxy).

    python experiments/tap_lab.py
"""

import json
import re
import socket
import sys
import threading
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cripto_agent.selo import Session  # noqa: E402
from cripto_agent.selo.sandbox import World  # noqa: E402
from cripto_agent.selo.transport import OrgClient, http_send, serve_agent, serve_org  # noqa: E402

AMOUNT = {"invoice": "INV-1", "amount_cents": 1000}


def read_http(sock):
    data = b""
    sock.settimeout(3)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                head, _, body = data.partition(b"\r\n\r\n")
                m = re.search(rb"Content-Length: (\d+)", head, re.I)
                if len(body) >= int(m.group(1)):
                    break
    except socket.timeout:
        pass
    return data


class Tap:
    """Proxy TCP. mode: passive | flip (altera 1 byte) | replay (reenvia a requisicao)."""

    def __init__(self, target_port, mode="passive"):
        self.target_port, self.mode = target_port, mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.captured = {}
        self.replay_status = None
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            client, _ = self.sock.accept()
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        upstream = socket.create_connection(("127.0.0.1", self.target_port))
        request = read_http(client)
        self.captured["A->B"] = request
        data = request
        if self.mode == "flip":
            i = len(request) - 40
            data = request[:i] + bytes([request[i] ^ 1]) + request[i + 1:]
        upstream.sendall(data)
        response = read_http(upstream)
        self.captured["B->A"] = response
        if self.mode == "replay":
            again = socket.create_connection(("127.0.0.1", self.target_port))
            again.sendall(request)
            again.settimeout(5)
            self.replay_status = again.recv(65536).split(b"\r\n")[0]
            again.close()
        client.sendall(response)
        client.close()
        upstream.close()


def build(mode):
    w = World(clock=time.time).standard()
    org_srv = serve_org(w.org)
    servers = {n: serve_agent(w.agents[n]) for n in ("erp", "web")}
    for server in (org_srv, *servers.values()):
        server.httpd.handle_error = lambda *a: None          # conexoes cortadas pelo no do meio
    tap = Tap(servers["erp"].httpd.server_port, mode)
    w.org.urls["erp"] = f"http://127.0.0.1:{tap.port}"        # A acredita que B esta no no do meio
    w.org.urls["web"] = servers["web"].url
    a = w.agents["assistant"]
    client = OrgClient(org_srv.url, w.org.params)
    a.directory, a.entry_provider = client.directory, client.entry
    token = w.agents["erp"].mint("erp.pay_invoice", [{"holder": "assistant"}])
    return w, a, tap, token, [org_srv, *servers.values()]


def session(w):
    s = Session()
    text = "Pague a fatura INV-1 de 1000 centavos."
    s.observe(w.principals["alice"].instruct(text), text)
    return s


def main():
    # 1) passivo: o que o tcpdump enxerga
    w, a, tap, token, servers = build("passive")
    out = a.call("erp", "erp.pay_invoice", AMOUNT, token, session(w), http_send)
    req, resp = tap.captured["A->B"], tap.captured["B->A"]
    wire = (req + resp).decode(errors="replace")
    print("resultado entregue a A:", out)
    print(f"\n[PASSIVO] {len(req)} bytes A->B, {len(resp)} bytes B->A. Inicio da requisicao capturada:")
    print(req[:230].decode(errors="replace").replace("\r\n", "\n"))
    for secret in ["INV-1", "1000", "pay_invoice", "amount_cents", "paid", "holder"]:
        print(f"  segredo  {secret!r:16} visivel no trafego? {secret in wire}")
    for meta in ["assistant", '"erp"', "acme", "epoch", "iat", "exp", "sig_pub"]:
        print(f"  metadado {meta!r:16} visivel no trafego? {meta in wire}")
    envelope = json.loads(req.partition(b"\r\n\r\n")[2])
    print("  campos do envelope:", list(envelope), "| cabecalho:", list(envelope["h"]))
    for s in servers:
        s.stop()

    # 2) ativo: altera 1 byte
    w, a, tap, token, servers = build("flip")
    try:
        a.call("erp", "erp.pay_invoice", AMOUNT, token, session(w), http_send)
        print("\n[ADULTERACAO] aceita?! (falha de seguranca)")
    except Exception as error:
        print("\n[ADULTERACAO de 1 byte no no do meio] A recebeu erro:", getattr(error, "code", error))
    print("  execucoes do token no ERP:", dict(w.agents["erp"]._uses))
    for s in servers:
        s.stop()

    # 3) ativo: replay
    w, a, tap, token, servers = build("replay")
    a.call("erp", "erp.pay_invoice", AMOUNT, token, session(w), http_send)
    time.sleep(0.5)
    print("\n[REPLAY pelo no do meio] resposta ao reenvio:", tap.replay_status)
    print("  execucoes do token no ERP:", dict(w.agents["erp"]._uses))
    for s in servers:
        s.stop()


if __name__ == "__main__":
    main()
