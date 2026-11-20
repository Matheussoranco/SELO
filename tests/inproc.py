"""Cenarios em processo com relogio injetavel (FakeClock).

Os sidecars continuam conversando pela fronteira de rede (HTTP em loopback), mas rodam no
processo do teste, com cofre em memoria e o relogio controlado pelo teste. Usado onde o
tempo importa (validade de Card, janela de rotacao, lista de revogacao, sessoes).
"""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from typing import Any

from selo.keystore import MemoryKeyStore
from selo.refagent import RefAgent
from selo.sidecar import Sidecar
from tests.harness import FakeClock


def send_message(text: str, rid: Any = 1, **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": str(uuid.uuid4()),
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            },
            **params,
        },
    }


def deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(a))
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class InNode:
    def __init__(
        self,
        world: InWorld,
        name: str,
        clock: FakeClock | None = None,
        cfg: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.clock = clock or world.clock
        self.agent = RefAgent(name, step=0.05).start()
        base = {
            "name": name,
            "state_dir": f"{world.tmp}/{name}",
            "agent": {"url": self.agent.url},
            "keystore": {"backend": "memory"},
            "local": {"mode": "http"},
        }
        self.cfg = deep_merge(base, cfg or {})
        self.keystore = MemoryKeyStore()
        self.sc = Sidecar(self.cfg, keystore=self.keystore, clock=self.clock).start()

    @property
    def url(self) -> str:
        return self.sc.base_url

    @property
    def agent_id(self) -> str:
        return self.sc.identity.agent_id

    def send(self, peer: InNode, text: str) -> dict[str, Any]:
        return self.sc.call(peer.url, send_message(text))

    def restart(self, cfg: dict[str, Any] | None = None) -> None:
        """Reinicia o sidecar com o mesmo cofre e o mesmo diretorio de estado.

        `cfg` (opcional) e mesclado a configuracao atual; chaves com valor None sao apagadas.
        """
        self.sc.stop()
        if cfg:
            self.cfg = deep_merge(self.cfg, cfg)
            for k, v in cfg.items():
                if v is None:
                    self.cfg.pop(k, None)
        self.sc = Sidecar(self.cfg, keystore=self.keystore, clock=self.clock).start()

    def join(
        self, org: Any, trust_orgs: list | None = None, descriptor: Any = None
    ) -> None:
        """Atesta este agente pela organizacao `org` e reinicia o sidecar como membro."""
        att = org.attest(self.agent_id, self.clock())
        self.restart(
            {
                "org": {
                    "descriptor": descriptor or org.descriptor(self.clock()),
                    "attestation": att,
                },
                "trust": {"orgs": trust_orgs or []},
            }
        )

    def stop(self) -> None:
        self.sc.stop()
        self.agent.stop()


class InWorld:
    def __init__(self, start: float | None = None) -> None:
        import time

        self.tmp = tempfile.mkdtemp(prefix="selo-inproc-")
        self.clock = FakeClock(start if start is not None else time.time())
        self.nodes: list = []

    def node(self, name: str, **kw: Any) -> InNode:
        n = InNode(self, name, **kw)
        self.nodes.append(n)
        return n

    def __enter__(self) -> InWorld:
        return self

    def __exit__(self, *exc: object) -> None:
        for n in self.nodes:
            try:
                n.stop()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)


def error_code(resp: dict[str, Any]) -> str | None:
    err = resp.get("error")
    return err.get("message") if isinstance(err, dict) else None
