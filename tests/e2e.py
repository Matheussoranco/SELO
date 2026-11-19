"""Montagem de cenarios de ponta a ponta: agentes de referencia + sidecars em processos separados.

Cada sidecar roda `python -m selo sidecar --config ...` com o cofre de chaves real do sistema
(DPAPI no Windows). O proxy do harness pode ficar na frente de qualquer sidecar: a URL publica
anunciada no Card passa a ser a do proxy.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import uuid
from typing import Any

from selo.local import LocalClient
from tests.harness import Proc, TapProxy

# Cofre real do sistema onde existe (DPAPI no Windows, Keychain no macOS, Secret Service com
# secret-tool); senao, o cofre em arquivo com senha de teste.
if sys.platform in ("win32", "darwin") or shutil.which("secret-tool"):
    KEYSTORE = "auto"
else:
    KEYSTORE = "file"
    os.environ.setdefault("SELO_KEY_PASSWORD", "senha-de-teste")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def send_message(
    text: str, rid: Any = 1, method: str = "SendMessage", **params: Any
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rid,
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


def rpc(method: str, rid: Any = 1, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


class Node:
    """Um agente de referencia e seu sidecar."""

    def __init__(
        self,
        world: World,
        name: str,
        proxied: bool = False,
        cfg: dict[str, Any] | None = None,
        start_agent: bool = True,
    ) -> None:
        self.world, self.name = world, name
        self.agent = (
            Proc(["-m", "selo.refagent", "--name", name]) if start_agent else None
        )
        self.state_dir = os.path.join(world.tmp, name)
        self.config_path = os.path.join(world.tmp, f"{name}.json")
        self.port = free_port()
        self.proxy: TapProxy | None = (
            TapProxy(f"http://127.0.0.1:{self.port}") if proxied else None
        )
        conf: dict[str, Any] = {
            "name": name,
            "state_dir": self.state_dir,
            "public": {"host": "127.0.0.1", "port": self.port},
            "agent": {
                "url": self.agent.info["url"] if self.agent else "http://127.0.0.1:9/"
            },
            "keystore": {"backend": KEYSTORE},
        }
        if self.proxy:
            conf["public"]["url"] = self.proxy.url
        for k, v in (cfg or {}).items():
            if isinstance(v, dict) and isinstance(conf.get(k), dict):
                conf[k] = {**conf[k], **v}
            else:
                conf[k] = v
        self.cfg = conf
        self.sidecar: Proc | None = None
        self.start()

    def write_config(self) -> None:
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(self.cfg, fh)

    def start(self) -> None:
        self.write_config()
        self.sidecar = Proc(["-m", "selo", "sidecar", "--config", self.config_path])
        self.info = self.sidecar.info
        self.client = LocalClient(info=self.info["local"])

    def restart(self, **cfg_changes: Any) -> None:
        self.stop_sidecar()
        self.cfg.update(cfg_changes)
        self.start()

    def stop_sidecar(self) -> None:
        if self.sidecar:
            self.sidecar.stop()
            self.sidecar = None

    @property
    def agent_id(self) -> str:
        return self.info["agent_id"]

    @property
    def url(self) -> str:
        return self.info["public_url"]

    def received(self) -> list[dict[str, Any]]:
        import urllib.request

        with urllib.request.urlopen(
            self.agent.info["url"] + "_debug/received", timeout=10
        ) as r:
            return json.loads(r.read())["received"]

    def debug(self) -> dict[str, Any]:
        import urllib.request

        with urllib.request.urlopen(
            self.agent.info["url"] + "_debug/received", timeout=10
        ) as r:
            return json.loads(r.read())

    def stop(self) -> None:
        self.stop_sidecar()
        if self.proxy:
            self.proxy.stop()
        if self.agent:
            self.agent.stop()


class World:
    """Agrupa nos de um teste e limpa tudo no fim (`with World() as w:`)."""

    def __init__(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="selo-e2e-")
        self.nodes: list[Node] = []

    def node(self, name: str, **kw: Any) -> Node:
        n = Node(self, name, **kw)
        self.nodes.append(n)
        return n

    def __enter__(self) -> World:
        return self

    def __exit__(self, *exc: object) -> None:
        for n in self.nodes:
            try:
                n.stop()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def logs(self) -> str:
        return "\n".join(
            f"--- {n.name}\n{n.sidecar.logs() if n.sidecar else ''}" for n in self.nodes
        )
