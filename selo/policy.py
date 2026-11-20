"""Gancho de politica (especificacao, secao 15).

A configuracao `policy` aponta para um chamavel `modulo:funcao`. Ele e chamado quatro vezes
por requisicao (entrada/saida x requisicao/resposta) com um `PolicyEvent` e:

* devolve `None` (ou qualquer valor) para permitir;
* levanta `PolicyDenied(motivo)` para recusar, o que vira o erro JSON-RPC `policy_denied`
  (-32093) devolvido a quem chamou.

Qualquer outra excecao do gancho tambem recusa (falha fechada). O evento so carrega
copias de dados publicos da requisicao: nada de chaves, sessoes ou do proprio sidecar. (Em
Python isso e uma fronteira de interface, nao de isolamento: codigo do gancho roda no
processo do sidecar e deve ser tratado como codigo confiavel.)
"""

from __future__ import annotations

import copy
import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from .errors import SeloError

Direction = Literal["inbound", "outbound"]
Stage = Literal["request", "response"]

DIRECTIONS: tuple[Direction, ...] = ("inbound", "outbound")
STAGES: tuple[Stage, ...] = ("request", "response")


class PolicyDenied(Exception):
    def __init__(self, reason: str = "") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PolicyEvent:
    direction: Direction  # inbound: o par chamou este agente; outbound: este agente chama o par
    stage: Stage  # request | response
    peer_id: str
    peer_org: str | None
    method: str | None
    rpc: Any  # copia profunda da requisicao ou resposta JSON-RPC


class NullHook:
    def check(
        self,
        direction: Direction,
        stage: Stage,
        peer_id: str,
        peer_org: str | None,
        rpc: Any,
        method: str | None = None,
    ) -> None:
        return None


class Hook(NullHook):
    def __init__(self, fn: Callable[[PolicyEvent], Any], name: str = "") -> None:
        self.fn, self.name = fn, name

    def check(
        self,
        direction: Direction,
        stage: Stage,
        peer_id: str,
        peer_org: str | None,
        rpc: Any,
        method: str | None = None,
    ) -> None:
        if method is None and isinstance(rpc, dict):
            method = rpc.get("method")
        ev = PolicyEvent(
            direction, stage, peer_id, peer_org, method, copy.deepcopy(rpc)
        )
        try:
            self.fn(ev)
        except PolicyDenied as e:
            raise SeloError("policy_denied", e.reason) from None
        except Exception as e:  # noqa: BLE001 - falha fechada
            raise SeloError(
                "policy_denied", f"erro no gancho: {type(e).__name__}"
            ) from None


def load_hook(spec: str | None) -> NullHook:
    if not spec:
        return NullHook()
    module, sep, attr = spec.partition(":")
    if not sep or not module or not attr:
        raise SeloError("bad_config", "policy deve ser 'modulo:funcao'")
    try:
        fn = getattr(importlib.import_module(module), attr)
    except (ImportError, AttributeError) as e:
        raise SeloError("bad_config", f"gancho de politica {spec!r}: {e}") from None
    if not callable(fn):
        raise SeloError("bad_config", f"{spec!r} nao e chamavel")
    return Hook(fn, spec)
