"""Notificacoes push (especificacao, secao 10).

Cliente (quem cria a configuracao push): troca a URL do webhook local do agente por
`<base publica>/selo/v1/push/<ref>` e guarda `ref -> (webhook, agent_id do servidor)`.

Servidor (quem recebe a configuracao): valida o destino ANTES de qualquer conexao
(forma `<base>/selo/v1/push/<ref>`; `<base>` e a do proprio requisitante ou consta de
`push.allowed_destinations`), depois verifica que ali ha um Card SELO, e troca a URL por
uma entrada local `http://127.0.0.1:<porta>/push-intake/<id>`. Quando o agente faz o POST
nessa entrada, o sidecar envia a notificacao como envelope `push` ao destino, que confere o
remetente e entrega ao webhook local com o token original.
"""

from __future__ import annotations

import copy
import os
import re
import urllib.parse
from typing import Any, Dict, Optional, Tuple

from . import envelope
from .card import CardInfo, normalize_base
from .crypto.primitives import b64u
from .errors import SeloError
from .net import Request, Response, is_loopback_host

PUSH_PATH = "/selo/v1/push/"
_REF = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _configs(rpc: Dict[str, Any]) -> list:
    """Referencias (dict mutavel) as configuracoes push dentro de uma requisicao."""
    method = rpc.get("method")
    params = rpc.get("params")
    if not isinstance(params, dict):
        return []
    if method == "CreateTaskPushNotificationConfig" and isinstance(
        params.get("url"), str
    ):
        return [params]
    if method in ("SendMessage", "SendStreamingMessage"):
        cfg = (params.get("configuration") or {}).get("taskPushNotificationConfig")
        if isinstance(cfg, dict) and isinstance(cfg.get("url"), str):
            return [cfg]
    return []


def _split_push_url(url: str) -> Tuple[str, str]:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.query or u.fragment:
        raise SeloError("push_destination_denied", "URL de push invalida")
    if not u.path.startswith(PUSH_PATH) or not _REF.match(u.path[len(PUSH_PATH) :]):
        raise SeloError("push_destination_denied", "URL nao e um endpoint push SELO")
    return normalize_base(f"{u.scheme}://{u.netloc}"), u.path[len(PUSH_PATH) :]


# -- cliente --------------------------------------------------------------------------------
def rewrite_outbound(sc: Any, rpc: Dict[str, Any], info: CardInfo) -> Dict[str, Any]:
    cfgs = _configs(rpc)
    if not cfgs:
        return rpc
    rpc = copy.deepcopy(rpc)
    for cfg in _configs(rpc):
        hook = urllib.parse.urlsplit(cfg["url"])
        if hook.path.startswith(PUSH_PATH):
            continue  # ja e um endpoint push SELO: o servidor decide pela lista de permitidos
        if hook.scheme not in ("http", "https") or not hook.hostname:
            raise SeloError("push_destination_denied", "webhook local invalido")
        if not is_loopback_host(hook.hostname):
            raise SeloError(
                "push_destination_denied",
                "o webhook do agente deve ser local (loopback)",
            )
        ref = b64u(os.urandom(16))
        sc.store.add_push_out(ref, cfg["url"], info.agent_id, sc.clock())
        cfg["url"] = f"{sc.base_url}{PUSH_PATH}{ref}"
    return rpc


def handle_delivery(sc: Any, req: Request, ref: str) -> Response:
    env = req.json()
    sc.capture("in", "envelope", env)
    opened, trust = sc.open_incoming(env, "push")
    target = sc.store.get_push_out(ref)
    push = opened.body.get("push")
    if target is None or not isinstance(push, dict) or push.get("ref") != ref:
        raise SeloError("unknown_push")
    webhook, server_id = target
    if opened.sender.agent_id != server_id:
        raise SeloError(
            "push_sender_mismatch", "notificacao de agente diferente do servidor"
        )
    status, _h, _b = sc.http.request(
        "POST",
        webhook,
        push.get("payload"),
        {"X-A2A-Notification-Token": str(push.get("token") or "")},
    )
    resp = envelope.seal(
        sender=sc.identity,
        sender_card_url=sc.base_url,
        recipient=opened.sender,
        body={"ack": status},
        t="resp",
        now=sc.clock(),
        re=opened.header["msg"],
        escrow=sc.escrow_target(trust),
    )
    sc.capture("out", "envelope", resp)
    return Response(200, resp)


# -- servidor -------------------------------------------------------------------------------
def _allowed(sc: Any, base: str, sender: CardInfo) -> bool:
    allowed = {
        normalize_base(u) for u in sc.cfg["push"].get("allowed_destinations") or []
    }
    return base == normalize_base(sender.base_url) or base in allowed


def rewrite_inbound(sc: Any, rpc: Dict[str, Any], sender: CardInfo) -> Dict[str, Any]:
    if not _configs(rpc):
        return rpc
    rpc = copy.deepcopy(rpc)
    for cfg in _configs(rpc):
        base, ref = _split_push_url(cfg["url"])
        if not _allowed(sc, base, sender):  # antes de qualquer conexao
            raise SeloError(
                "push_destination_denied", f"{base} fora de push.allowed_destinations"
            )
        try:
            dest, _trust = sc.peers.get(base)
        except SeloError as e:
            raise SeloError(
                "push_destination_denied", f"{base} nao e um endpoint SELO ({e.code})"
            ) from None
        pid = b64u(os.urandom(16))
        sc.store.add_push_in(
            pid,
            base,
            dest.agent_id,
            ref,
            str(cfg.get("token") or ""),
            sender.agent_id,
            sc.clock(),
        )
        cfg["url"] = f"http://127.0.0.1:{sc.intake.port}/push-intake/{pid}"
    return rpc


def handle_intake(sc: Any, req: Request) -> Response:
    if req.method != "POST" or not req.path.startswith("/push-intake/"):
        return Response(404, {"error": "not_found"})
    entry: Optional[Dict[str, str]] = sc.store.get_push_in(
        req.path[len("/push-intake/") :]
    )
    if entry is None:
        return Response(404, {"error": "not_found"})
    payload = req.json()
    try:
        info, trust = sc.peers.get(entry["dest_url"], expected_id=entry["dest_id"])
        sc.send_envelope(
            info,
            trust,
            {
                "push": {
                    "ref": entry["ref"],
                    "token": entry["token"],
                    "payload": payload,
                }
            },
            t="push",
            path=PUSH_PATH + entry["ref"],
        )
    except SeloError as e:
        return Response(502, {"error": e.code})
    return Response(200, {})
