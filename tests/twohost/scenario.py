"""Validacao final da v1 (ticket #18): dois hosts em redes separadas + falhas injetadas.

Roda como root numa maquina Linux (testado na WSL2). Cria tres namespaces de rede, o mesmo
mecanismo de isolamento dos conteineres:

    host-a (10.10.1.2/24) --- roteador (10.10.1.1 | 10.10.2.1) --- host-b (10.10.2.2/24)

Cada host tem a sua pilha de rede, o seu loopback, o seu agente de referencia e o seu
sidecar. Os sidecars so se falam pelo roteador, por HTTPS (TLS obrigatorio fora do
loopback), com uma CA de teste. Uma organizacao ("acme", servidor da lista de revogacao no
host-a) atesta os dois agentes.

Uso:  sudo python3 tests/twohost/scenario.py [--out relatorio.json]

Sai com codigo 0 se todas as verificacoes passarem. Sempre remove os namespaces no fim.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from selo.local import LocalClient  # noqa: E402
from tests.harness import Proc  # noqa: E402
from tests.tlsutil import make_ca, make_server_cert  # noqa: E402

NS = {"a": "selo-host-a", "b": "selo-host-b", "r": "selo-router"}
IP = {"a": "10.10.1.2", "b": "10.10.2.2"}
PASSWORD = "senha-da-validacao"


def sh(*cmd: str, check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout


def ns_exec(ns: str) -> list:
    return ["ip", "netns", "exec", NS[ns]]


def setup_network() -> None:
    teardown_network()
    for n in NS.values():
        sh("ip", "netns", "add", n)
    sh("ip", "link", "add", "va", "type", "veth", "peer", "name", "ra")
    sh("ip", "link", "add", "vb", "type", "veth", "peer", "name", "rb")
    sh("ip", "link", "set", "va", "netns", NS["a"])
    sh("ip", "link", "set", "ra", "netns", NS["r"])
    sh("ip", "link", "set", "vb", "netns", NS["b"])
    sh("ip", "link", "set", "rb", "netns", NS["r"])
    for host, dev, addr, gw in (
        ("a", "va", "10.10.1.2/24", "10.10.1.1"),
        ("b", "vb", "10.10.2.2/24", "10.10.2.1"),
    ):
        sh(*ns_exec(host), "ip", "addr", "add", addr, "dev", dev)
        sh(*ns_exec(host), "ip", "link", "set", dev, "up")
        sh(*ns_exec(host), "ip", "link", "set", "lo", "up")
        sh(*ns_exec(host), "ip", "route", "add", "default", "via", gw)
    sh(*ns_exec("r"), "ip", "addr", "add", "10.10.1.1/24", "dev", "ra")
    sh(*ns_exec("r"), "ip", "addr", "add", "10.10.2.1/24", "dev", "rb")
    for dev in ("ra", "rb", "lo"):
        sh(*ns_exec("r"), "ip", "link", "set", dev, "up")
    sh(*ns_exec("r"), "sysctl", "-w", "net.ipv4.ip_forward=1")


def teardown_network() -> None:
    for n in NS.values():
        subprocess.run(["ip", "netns", "del", n], capture_output=True)


def ns_http(ns: str, url: str, body=None) -> dict:
    """GET/POST em loopback DENTRO de um namespace (o agente de referencia so ouve la)."""
    code = (
        "import json,sys,urllib.request as u;"
        "d=sys.argv[2].encode() if len(sys.argv)>2 else None;"
        "r=u.urlopen(u.Request(sys.argv[1],data=d,headers={'Content-Type':'application/json'}),timeout=10);"
        "print(r.read().decode())"
    )
    args = [*ns_exec(ns), sys.executable, "-c", code, url] + (
        [json.dumps(body)] if body is not None else []
    )
    return json.loads(sh(*args))


def ns_post(ns: str, url: str, body: dict, ca: str):
    """POST HTTPS feito de dentro de um host (o namespace raiz nao tem rota para a rede)."""
    code = (
        "import json,sys;from selo.net import HttpClient;"
        "st,b=HttpClient(ca_file=sys.argv[2]).json('POST',sys.argv[1],json.loads(sys.stdin.read()));"
        "print(json.dumps([st,b]))"
    )
    r = subprocess.run(
        [*ns_exec(ns), sys.executable, "-c", code, url, ca],
        input=json.dumps(body),
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return tuple(json.loads(r.stdout))


def msg(text: str, method: str = "SendMessage", **params) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "message": {
                "messageId": str(uuid.uuid4()),
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            },
            **params,
        },
    }


def rpc(method: str, **params) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


class Report:
    def __init__(self) -> None:
        self.checks: list = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        print(
            ("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""),
            flush=True,
        )

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)


class Host:
    def __init__(self, key: str, work: Path, pki: dict, env: dict) -> None:
        self.key, self.work, self.pki, self.env = key, work, pki, env
        self.agent = Proc(
            ["-m", "selo.refagent", "--name", f"agente-{key}", "--step", "0.2"],
            prefix=ns_exec(key),
            env=env,
        )
        self.cfg_path = work / f"{key}.json"
        self.cfg = {
            "name": f"host-{key}",
            "state_dir": str(work / f"state-{key}"),
            "public": {
                "host": IP[key],
                "port": 8443,
                "tls": {"cert": pki[key][0], "key": pki[key][1]},
            },
            "local": {"mode": "unix"},
            "agent": {"url": self.agent.info["url"]},
            "keystore": {"backend": "file"},
            "tls": {"ca_file": pki["ca"]},
            "capture_path": str(work / f"capture-{key}.jsonl"),
        }
        self.sidecar = None
        self.start()

    def start(self) -> None:
        self.cfg_path.write_text(json.dumps(self.cfg))
        self.sidecar = Proc(
            ["-m", "selo", "sidecar", "--config", str(self.cfg_path)],
            prefix=ns_exec(self.key),
            env=self.env,
        )
        self.info = self.sidecar.info
        self.client = LocalClient(info=self.info["local"])

    def stop_sidecar(self) -> None:
        if self.sidecar:
            self.sidecar.stop()
            self.sidecar = None

    @property
    def url(self) -> str:
        return self.info["public_url"]

    @property
    def agent_id(self) -> str:
        return self.info["agent_id"]

    def debug(self) -> dict:
        return ns_http(self.key, self.agent.info["url"] + "_debug/received")

    def captured(self, kind: str, direction: str) -> list:
        path = Path(self.cfg["capture_path"])
        if not path.exists():
            return []
        recs = [
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        ]
        return [r["data"] for r in recs if r["kind"] == kind and r["dir"] == direction]

    def stop(self) -> None:
        self.stop_sidecar()
        self.agent.stop()


def flip_ct(m: dict) -> dict:
    m = json.loads(json.dumps(m))
    raw = bytearray(base64.urlsafe_b64decode(m["ct"] + "=" * (-len(m["ct"]) % 4)))
    raw[0] ^= 1
    m["ct"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    return m


def wait(fn, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    return fn()


def run(report: Report, work: Path) -> None:
    env = {"SELO_KEY_PASSWORD": PASSWORD, "PYTHONDONTWRITEBYTECODE": "1"}
    os.environ.update(env)
    # -- PKI de teste --------------------------------------------------------------------
    ca, ca_cert, ca_key = make_ca(str(work))
    pki = {"ca": ca}
    for k in ("a", "b"):
        pki[k] = make_server_cert(str(work), f"host-{k}", ca_cert, ca_key, [IP[k]])

    # -- organizacao (servidor da lista no host-a, HTTPS) --------------------------------
    org_dir = work / "org"
    rev_url = f"https://{IP['a']}:9443/revocations"
    out = sh(
        sys.executable,
        "-m",
        "selo",
        "org",
        "init",
        "--dir",
        str(org_dir),
        "--name",
        "acme",
        "--revocations-url",
        rev_url,
        "--keystore",
        "file",
    )
    descriptor = json.loads(out)["descriptor"]

    def org_server():
        return Proc(
            [
                "-m",
                "selo",
                "org",
                "serve",
                "--dir",
                str(org_dir),
                "--keystore",
                "file",
                "--host",
                IP["a"],
                "--port",
                "9443",
                "--tls-cert",
                pki["a"][0],
                "--tls-key",
                pki["a"][1],
                "--ttl",
                "3",
            ],
            prefix=ns_exec("a"),
            env=env,
        )

    orgsrv = org_server()

    # -- hosts: primeira subida gera a identidade; depois a organizacao atesta -----------
    hosts = {k: Host(k, work, pki, env) for k in ("a", "b")}
    try:
        for h in hosts.values():
            att = json.loads(
                sh(
                    sys.executable,
                    "-m",
                    "selo",
                    "org",
                    "attest",
                    "--dir",
                    str(org_dir),
                    "--keystore",
                    "file",
                    "--agent-id",
                    h.agent_id,
                )
            )
            h.stop_sidecar()
            h.cfg["org"] = {"descriptor": descriptor, "attestation": att}
            h.start()
        a, b = hosts["a"], hosts["b"]
        report.check(
            "hosts em redes separadas",
            a.url.startswith("https://10.10.1.2")
            and b.url.startswith("https://10.10.2.2"),
            f"{a.url} | {b.url}",
        )
        route = sh(*ns_exec("a"), "ip", "route", "get", IP["b"])
        report.check(
            "trafego passa pelo roteador", "via 10.10.1.1" in route, route.strip()
        )

        # 1. mensagem
        r = a.client.call(b.url, msg("ola, outro host"))
        rec = b.debug()["received"]
        report.check(
            "SendMessage entre hosts",
            "error" not in r
            and rec
            and rec[-1]["text"] == "ola, outro host"
            and rec[-1]["sender"] == a.agent_id
            and rec[-1]["org"] == "acme",
            json.dumps(r)[:200],
        )

        # 2. tarefa longa, GetTask e CancelTask (sessao)
        task = a.client.call(b.url, msg("lenta 3"))["result"]["task"]
        done = wait(
            lambda: (
                a.client.call(b.url, rpc("GetTask", id=task["id"]))
                .get("result", {})
                .get("status", {})
                .get("state")
                == "TASK_STATE_COMPLETED"
            )
        )
        report.check("tarefa longa conclui (GetTask pela sessao)", bool(done))
        other = a.client.call(b.url, msg("lenta 100"))["result"]["task"]
        c = a.client.call(b.url, rpc("CancelTask", id=other["id"]))
        report.check(
            "CancelTask",
            c.get("result", {}).get("status", {}).get("state") == "TASK_STATE_CANCELED",
        )
        report.check(
            "sessao estabelecida entre hosts", bool(a.captured("handshake", "out"))
        )

        # 3. streaming
        evs = list(
            a.client.stream(b.url, msg("lenta 3", method="SendStreamingMessage"))
        )
        texts = [
            e["result"]["artifactUpdate"]["artifact"]["parts"][0]["text"]
            for e in evs
            if "artifactUpdate" in e.get("result", {})
        ]
        report.check(
            "streaming SSE em ordem",
            texts == ["passo 1/3", "passo 2/3", "passo 3/3"]
            and evs[-1]["result"]["statusUpdate"]["status"]["state"]
            == "TASK_STATE_COMPLETED",
            str(texts),
        )

        # 4. push para o webhook do agente A, atravessando a rede
        hook = a.agent.info["url"] + "_webhook"
        t = a.client.call(
            b.url,
            msg(
                "lenta 2",
                configuration={
                    "taskPushNotificationConfig": {"url": hook, "token": "tok-2h"}
                },
            ),
        )["result"]["task"]
        got = wait(
            lambda: [
                w
                for w in a.debug()["webhook"]
                if w["event"].get("statusUpdate", {}).get("taskId") == t["id"]
                and w["event"]["statusUpdate"]["status"]["state"]
                == "TASK_STATE_COMPLETED"
            ]
        )
        report.check(
            "push entregue ao webhook do outro host",
            bool(got) and got[0]["token"] == "tok-2h",
        )

        # 5. rotacao de chaves de B (sidecar parado), A continua
        b.stop_sidecar()
        sh(sys.executable, "-m", "selo", "rotate", "--config", str(b.cfg_path))
        b.start()
        r = a.client.call(b.url, msg("depois da rotacao"))
        report.check("rotacao de chaves de B", "error" not in r, json.dumps(r)[:200])

        # -- falhas injetadas ---------------------------------------------------------------
        envs = [
            e
            for e in a.captured("envelope", "out")
            if e.get("h", {}).get("t") == "req" and e["h"]["recipient"] == b.agent_id
        ]
        st, body = ns_post("a", b.url + "/selo/v1/envelope", envs[-1], ca)
        report.check(
            "replay de envelope rejeitado",
            st == 409 and body.get("error") == "replay",
            f"{st} {body}",
        )
        st, body = ns_post("a", b.url + "/selo/v1/envelope", flip_ct(envs[-1]), ca)
        report.check("envelope adulterado rejeitado", st == 400, f"{st} {body}")

        a.client.call(b.url, rpc("GetTask", id=task["id"]))
        a.client.call(b.url, rpc("GetTask", id=task["id"]))
        sess = a.captured("session", "out")
        old = sess[-2]
        st, body = ns_post("a", f"{b.url}/selo/v1/session/{old['sid']}", old, ca)
        report.check(
            "mensagem de sessao antiga (reordenada) rejeitada",
            st == 400,
            f"{st} {body}",
        )
        st, body = ns_post(
            "a", f"{b.url}/selo/v1/session/{sess[-1]['sid']}", flip_ct(sess[-1]), ca
        )
        report.check(
            "mensagem de sessao adulterada rejeitada", st == 400, f"{st} {body}"
        )

        # relogio dessincronizado: um terceiro sidecar no host-a, 10 minutos adiantado
        a.stop_sidecar()
        a.cfg["clock_offset"] = 600
        a.start()
        r = a.client.call(b.url, msg("do futuro"))
        report.check(
            "relogio dessincronizado rejeitado",
            "error" in r,
            (r.get("error") or {}).get("message", ""),
        )
        # Card vencido: validade curta e relogio atrasado
        a.stop_sidecar()
        a.cfg["clock_offset"] = -3 * 3600
        a.cfg["card"] = {"validity": 3600}
        a.start()
        time.sleep(31)  # o Card antigo de A expira do cache de B (30 s); B busca o novo
        r = b.client.call(a.url, msg("para um Card vencido"))
        report.check(
            "Card vencido derruba a conexao",
            (r.get("error") or {}).get("message") == "card_stale",
            (r.get("error") or {}).get("message", ""),
        )
        a.stop_sidecar()
        a.cfg.pop("clock_offset")
        a.cfg.pop("card")
        a.start()
        report.check(
            "volta ao normal com o relogio certo",
            "error" not in a.client.call(b.url, msg("ok")),
        )

        # lista de revogacao vencida (servidor fora do ar) -> falha fechada
        orgsrv.stop()
        time.sleep(4)
        r = a.client.call(b.url, msg("sem lista fresca"))
        report.check(
            "lista de revogacao vencida: falha fechada",
            (r.get("error") or {}).get("message") == "revocations_stale",
            (r.get("error") or {}).get("message", ""),
        )
        orgsrv = org_server()

        # revogacao de A pela organizacao
        sh(
            sys.executable,
            "-m",
            "selo",
            "org",
            "revoke",
            "--dir",
            str(org_dir),
            "--keystore",
            "file",
            "--agent-id",
            a.agent_id,
        )
        time.sleep(4)
        r = b.client.call(a.url, msg("para um agente revogado"))
        report.check(
            "agente revogado pela organizacao rejeitado",
            (r.get("error") or {}).get("message") == "peer_revoked",
            (r.get("error") or {}).get("message", ""),
        )

        # nada em claro: o conteudo nunca aparece nas capturas da rede (so cifrado)
        raw = (
            Path(a.cfg["capture_path"]).read_text()
            + Path(b.cfg["capture_path"]).read_text()
        )
        report.check(
            "capturas nao contem texto claro",
            "ola, outro host" not in raw
            and "passo 2/3" not in raw
            and "tok-2h" not in raw,
        )
    finally:
        for h in hosts.values():
            try:
                h.stop()
            except Exception:
                pass
        orgsrv.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    if os.geteuid() != 0 or not shutil.which("ip"):
        print("precisa de root e do iproute2 (ip netns)", file=sys.stderr)
        return 2
    import cryptography

    os.environ["PYTHONPATH"] = str(ROOT)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    report = Report()
    work = Path(tempfile.mkdtemp(prefix="selo-2h-"))
    started = time.time()
    try:
        setup_network()
        run(report, work)
    except Exception:
        report.check(
            "cenario executou sem excecao", False, traceback.format_exc()[-1500:]
        )
    finally:
        teardown_network()
        shutil.rmtree(work, ignore_errors=True)
    result = {
        "ok": report.ok,
        "checks": report.checks,
        "duration_s": round(time.time() - started, 1),
        "environment": {
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kernel": platform.release(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "topology": "3 network namespaces: host-a 10.10.1.2/24, router, host-b 10.10.2.2/24; HTTPS with a test CA",
        },
    }
    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        )
    print(
        json.dumps(
            {
                "ok": result["ok"],
                "passed": sum(c["ok"] for c in report.checks),
                "total": len(report.checks),
            }
        )
    )
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
