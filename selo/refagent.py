"""Agente A2A 1.0 de referencia (so biblioteca padrao), usado em testes e demonstracoes.

Fica atras de um sidecar SELO e fala JSON-RPC A2A 1.0 em loopback. Comportamento:

* texto qualquer: tarefa concluida na hora, com o artefato ``eco: <texto>``;
* texto ``lenta N``: tarefa em ``TASK_STATE_WORKING`` que avanca N passos (0,2 s cada) e
  termina em ``TASK_STATE_COMPLETED``, ou ``TASK_STATE_CANCELED`` se cancelada;
* streaming (``SendStreamingMessage``/``SubscribeToTask``) em SSE, com eventos
  ``task``, ``statusUpdate`` e ``artifactUpdate``, como o a2a-sdk;
* notificacoes push (configuracoes por tarefa) com o cabecalho ``X-A2A-Notification-Token``.

``GET /_debug/received`` devolve as mensagens recebidas e o cabecalho ``X-Selo-Sender`` de
cada uma (so para testes). Execute com ``python -m selo.refagent --name X``; o processo
anuncia ``READY {"url": ...}``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import queue
import threading
import time
import urllib.request
import uuid
from collections.abc import Iterator
from typing import Any

from .net import HttpServer, Request, Response, sse_event

FINAL = {
    "TASK_STATE_COMPLETED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_FAILED",
    "TASK_STATE_REJECTED",
}


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _text(message: dict[str, Any]) -> str:
    return "".join(
        p.get("text", "") for p in message.get("parts", []) if isinstance(p, dict)
    )


class RefAgent:
    def __init__(
        self, name: str = "ref", step: float = 0.2, inbound_token: str | None = None
    ) -> None:
        self.name, self.step, self.inbound_token = name, step, inbound_token
        self.tasks: dict[str, dict[str, Any]] = {}
        self.push: dict[str, dict[str, dict[str, Any]]] = {}  # task_id -> {cfg_id: cfg}
        self.subscribers: dict[str, list[queue.Queue]] = {}
        self.received: list[dict[str, Any]] = []
        self.pushes_sent: list[dict[str, Any]] = []
        self.webhook: list[
            dict[str, Any]
        ] = []  # notificacoes push recebidas por este agente
        self._lock = threading.RLock()
        self.server: HttpServer | None = None

    # -- servidor -------------------------------------------------------------------------
    def start(self, host: str = "127.0.0.1", port: int = 0) -> RefAgent:
        self.server = HttpServer(host, port, self.handle).start()
        return self

    @property
    def url(self) -> str:
        assert self.server is not None
        return f"http://127.0.0.1:{self.server.port}/"

    def stop(self) -> None:
        if self.server:
            self.server.stop()

    def handle(self, req: Request) -> Response:
        if req.method == "GET" and req.path == "/_debug/received":
            with self._lock:
                return Response(
                    200,
                    {
                        "received": self.received,
                        "pushes_sent": self.pushes_sent,
                        "webhook": self.webhook,
                    },
                )
        if req.method == "POST" and req.path == "/_webhook":
            with self._lock:
                self.webhook.append(
                    {
                        "token": req.headers.get("x-a2a-notification-token"),
                        "event": req.json(),
                    }
                )
            return Response(200, {})
        if req.method != "POST":
            return Response(404, {"error": "not_found"})
        if (
            self.inbound_token
            and req.headers.get("authorization") != f"Bearer {self.inbound_token}"
        ):
            return Response(401, {"error": "unauthorized"})
        try:
            rpc = req.json()
        except Exception:  # noqa: BLE001
            return Response(200, _err(None, -32700, "parse error"))
        rid, method, params = rpc.get("id"), rpc.get("method"), rpc.get("params") or {}
        try:
            if method == "SendMessage":
                return Response(200, _ok(rid, {"task": self._send(params, req)}))
            if method == "SendStreamingMessage":
                task = self._send(params, req)
                return self._sse(rid, task["id"], first={"task": task})
            if method == "SubscribeToTask":
                task = self._task(params.get("id"))
                return self._sse(rid, task["id"], first={"task": task})
            if method == "GetTask":
                return Response(200, _ok(rid, self._task(params.get("id"))))
            if method == "ListTasks":
                with self._lock:
                    return Response(200, _ok(rid, {"tasks": list(self.tasks.values())}))
            if method == "CancelTask":
                return Response(200, _ok(rid, self._cancel(params.get("id"))))
            if method == "CreateTaskPushNotificationConfig":
                return Response(200, _ok(rid, self._add_push(params)))
            if method == "GetTaskPushNotificationConfig":
                cfg = self.push.get(params.get("taskId"), {}).get(params.get("id"))
                if cfg is None:
                    return Response(200, _err(rid, -32001, "config not found"))
                return Response(200, _ok(rid, cfg))
            if method == "ListTaskPushNotificationConfigs":
                return Response(
                    200,
                    _ok(
                        rid,
                        {
                            "configs": list(
                                self.push.get(params.get("taskId"), {}).values()
                            )
                        },
                    ),
                )
            if method == "DeleteTaskPushNotificationConfig":
                self.push.get(params.get("taskId"), {}).pop(params.get("id"), None)
                return Response(200, _ok(rid, {}))
            return Response(200, _err(rid, -32601, "method not found"))
        except KeyError as e:
            return Response(200, _err(rid, -32001, f"task not found: {e}"))

    # -- tarefas --------------------------------------------------------------------------
    def _send(self, params: dict[str, Any], req: Request) -> dict[str, Any]:
        msg = params.get("message") or {}
        text = _text(msg)
        with self._lock:
            self.received.append(
                {
                    "text": text,
                    "sender": req.headers.get("x-selo-sender"),
                    "org": req.headers.get("x-selo-org"),
                    "message": msg,
                }
            )
        task_id, ctx = str(uuid.uuid4()), msg.get("contextId") or str(uuid.uuid4())
        user_msg = dict(msg, taskId=task_id, contextId=ctx)
        task = {
            "id": task_id,
            "contextId": ctx,
            "status": {"state": "TASK_STATE_SUBMITTED", "timestamp": _now()},
            "artifacts": [],
            "history": [user_msg],
        }
        with self._lock:
            self.tasks[task_id] = task
        cfg = (params.get("configuration") or {}).get("taskPushNotificationConfig")
        if cfg:
            self._add_push(dict(cfg, taskId=task_id))
        if text.startswith("lenta"):
            parts = text.split()
            steps = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5
            self._set_state(task_id, "TASK_STATE_WORKING")
            threading.Thread(
                target=self._work, args=(task_id, steps), daemon=True
            ).start()
        else:
            self._artifact(task_id, f"eco: {text}")
            self._set_state(task_id, "TASK_STATE_COMPLETED")
        with self._lock:
            return json.loads(json.dumps(self.tasks[task_id]))

    def _work(self, task_id: str, steps: int) -> None:
        for i in range(steps):
            time.sleep(self.step)
            with self._lock:
                if self.tasks[task_id]["status"]["state"] in FINAL:
                    return
            self._artifact(
                task_id, f"passo {i + 1}/{steps}", append=i > 0, last=i == steps - 1
            )
        self._set_state(task_id, "TASK_STATE_COMPLETED")

    def _task(self, task_id: Any) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.tasks[task_id]))

    def _cancel(self, task_id: Any) -> dict[str, Any]:
        with self._lock:
            task = self.tasks[task_id]
            if task["status"]["state"] not in FINAL:
                self._set_state(task_id, "TASK_STATE_CANCELED")
            return json.loads(json.dumps(task))

    def _set_state(self, task_id: str, state: str) -> None:
        with self._lock:
            task = self.tasks[task_id]
            task["status"] = {"state": state, "timestamp": _now()}
            ev = {
                "statusUpdate": {
                    "taskId": task_id,
                    "contextId": task["contextId"],
                    "status": task["status"],
                }
            }
        self._emit(task_id, ev, final=state in FINAL)

    def _artifact(
        self, task_id: str, text: str, append: bool = False, last: bool = True
    ) -> None:
        with self._lock:
            task = self.tasks[task_id]
            art = {
                "artifactId": f"{task_id}-out",
                "name": "saida",
                "parts": [{"text": text}],
            }
            if append and task["artifacts"]:
                task["artifacts"][0]["parts"].append({"text": text})
            else:
                task["artifacts"] = [art]
            ev = {
                "artifactUpdate": {
                    "taskId": task_id,
                    "contextId": task["contextId"],
                    "artifact": art,
                    "append": append,
                    "lastChunk": last,
                }
            }
        self._emit(task_id, ev, final=False)

    def _emit(self, task_id: str, ev: dict[str, Any], final: bool) -> None:
        with self._lock:
            subs = list(self.subscribers.get(task_id, []))
            cfgs = list(self.push.get(task_id, {}).values())
        for q in subs:
            q.put((ev, final))
        for cfg in cfgs:
            threading.Thread(
                target=self._send_push, args=(cfg, ev), daemon=True
            ).start()

    def _send_push(self, cfg: dict[str, Any], ev: dict[str, Any]) -> None:
        req = urllib.request.Request(
            cfg["url"],
            data=json.dumps(ev).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-A2A-Notification-Token": cfg.get("token", ""),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status = r.status
        except Exception as e:  # noqa: BLE001 - o teste inspeciona o resultado
            status = f"erro: {e}"
        with self._lock:
            self.pushes_sent.append({"url": cfg["url"], "event": ev, "status": status})

    def _add_push(self, params: dict[str, Any]) -> dict[str, Any]:
        task_id = params.get("taskId")
        with self._lock:
            if task_id not in self.tasks:
                raise KeyError(task_id)
            cfg = {
                "taskId": task_id,
                "id": params.get("id") or str(uuid.uuid4()),
                "url": params["url"],
                "token": params.get("token", ""),
            }
            self.push.setdefault(task_id, {})[cfg["id"]] = cfg
            return dict(cfg)

    # -- streaming ------------------------------------------------------------------------
    def _sse(self, rid: Any, task_id: str, first: dict[str, Any]) -> Response:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self.subscribers.setdefault(task_id, []).append(q)
            already_final = self.tasks[task_id]["status"]["state"] in FINAL

        def gen() -> Iterator[bytes]:
            try:
                yield sse_event(json.dumps(_ok(rid, first)))
                if already_final:
                    return
                while True:
                    ev, final = q.get(timeout=120)
                    yield sse_event(json.dumps(_ok(rid, ev)))
                    if final:
                        return
            finally:
                with self._lock:
                    if q in self.subscribers.get(task_id, []):
                        self.subscribers[task_id].remove(q)

        return Response(200, content_type="text/event-stream", stream=gen())


def _ok(rid: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def main() -> None:
    ap = argparse.ArgumentParser(description="Agente A2A de referencia")
    ap.add_argument("--name", default="ref")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--step", type=float, default=0.2)
    args = ap.parse_args()
    agent = RefAgent(args.name, args.step).start(port=args.port)
    print("READY " + json.dumps({"url": agent.url}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
