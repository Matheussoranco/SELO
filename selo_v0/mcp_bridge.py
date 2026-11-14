"""Ponte MCP -> SELO: coloca servidores MCP existentes (stdio) atras do protocolo SELO, sem alterar o servidor.

  servidor MCP  <-stdio JSON-RPC->  McpStdioClient  <-handlers->  Agent SELO (host)  <-envelopes->  agentes

O ADMINISTRADOR decide o que entra: cada tool listada pelo servidor vira um manifesto, passa pelo
linter e so e admitida (assinada pela organizacao e registrada no log Merkle) se o criterio aprovar.
Os rotulos vem das *annotations* do MCP (readOnlyHint, openWorldHint; padroes da especificacao:
destrutiva e mundo aberto), que sao DICAS do servidor: a organizacao pode sobrescreve-las.

O cliente stdio e minimo e independente do SDK (mensagens JSON-RPC delimitadas por quebra de linha).
"""

from __future__ import annotations

import json
import math
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .lint import Finding, lint_manifests
from .manifest import new_manifest
from .util import SeloError

PROTOCOL_VERSION = "2025-06-18"


class McpError(SeloError):
    pass


class McpStdioClient:
    def __init__(self, command: List[str], env: Optional[Dict[str, str]] = None, timeout: float = 30.0):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout deve ser positivo e finito")
        self.command, self.env, self.timeout = command, env, timeout
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._next_id = 0
        self.server_info: Dict[str, Any] = {}

    def start(self) -> "McpStdioClient":
        if self._proc is not None:
            raise McpError("mcp_started")
        self._proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, env=self.env, text=True, encoding="utf-8",
                                      bufsize=1)
        try:
            result = self.request("initialize", {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "selo-bridge", "version": "0.2"}})
            self.server_info = result.get("serverInfo", {})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            return self
        except Exception:
            self.close()
            raise

    def _send(self, message: Dict[str, Any]) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                raise McpError("mcp_closed")
            self._next_id += 1
            ident = self._next_id
            outcome = queue.Queue(maxsize=1)

            def exchange():
                try:
                    outcome.put((self._exchange(ident, method, params), None))
                except Exception as error:
                    outcome.put((None, error))

            # Pipes de subprocessos no Windows nao suportam select(). O prazo
            # cobre escrita e leitura, inclusive servidores que nunca enviam '\n'.
            worker = threading.Thread(target=exchange, daemon=True)
            worker.start()
            try:
                result, error = outcome.get(timeout=self.timeout)
            except queue.Empty:
                self.close()
                worker.join(timeout=1)
                raise McpError("mcp_timeout") from None
            if error is not None:
                if not isinstance(error, McpError) or error.code != "mcp_error":
                    self.close()
                raise error
            return result

    def _exchange(self, ident, method, params):
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise McpError("mcp_closed", "o servidor MCP encerrou")
            try:
                message = json.loads(line)
            except ValueError:
                raise McpError("mcp_protocol") from None
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise McpError("mcp_protocol")
            if "method" in message:
                if "id" in message:
                    self._send({"jsonrpc": "2.0", "id": message["id"], "error": {
                        "code": -32601, "message": "metodo nao suportado"}})
                continue
            if type(message.get("id")) is not int or message["id"] != ident:
                continue
            if ("result" in message) == ("error" in message):
                raise McpError("mcp_protocol")
            if "error" in message:
                if not isinstance(message["error"], dict):
                    raise McpError("mcp_protocol")
                raise McpError("mcp_error", str(message["error"].get("message", ""))[:200])
            if not isinstance(message["result"], dict):
                raise McpError("mcp_protocol")
            return message["result"]

    def list_tools(self) -> List[Dict[str, Any]]:
        tools, cursor, seen = [], None, set()
        while True:
            page = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(page.get("tools", []))
            cursor = page.get("nextCursor")
            if not cursor:
                return tools
            if not isinstance(cursor, str) or cursor in seen:
                raise McpError("mcp_pagination")
            seen.add(cursor)

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.kill()
            self._proc.wait()
            for stream in (self._proc.stdin, self._proc.stdout):
                if stream is not None:
                    stream.close()


def result_to_text(result: Dict[str, Any]) -> str:
    parts = []
    for block in result.get("content", []):
        parts.append(block["text"] if block.get("type") == "text" and "text" in block
                     else f"[{block.get('type', 'conteudo')} omitido]")
    if not parts and "structuredContent" in result:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(parts)


def tool_to_manifest(tool: Dict[str, Any], publisher: str,
                     overrides: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Tool MCP -> manifesto SELO. Padroes do MCP: readOnlyHint=false, destructiveHint=true,
    openWorldHint=true (a especificacao assume o pior caso quando nada e declarado)."""
    ann = tool.get("annotations") or {}
    if not isinstance(ann, dict):
        raise McpError("mcp_annotations")
    for hint in ("readOnlyHint", "openWorldHint"):
        if hint in ann and type(ann[hint]) is not bool:
            raise McpError("mcp_annotations", hint)
    read_only = ann.get("readOnlyHint", False)
    open_world = ann.get("openWorldHint", True)
    effect = "read" if read_only else ("external" if open_world else "write")
    taint_out = ["EXTERNAL"] if (read_only and open_world) else []
    forbid = [] if read_only else ["EXTERNAL"]
    fields = dict(taint_out=taint_out, forbid_taint=forbid, effect=effect)
    fields.update((overrides or {}).get(tool["name"], {}))
    schema = json.loads(json.dumps(tool.get("inputSchema") or {"type": "object", "properties": {}}))
    schema.setdefault("required", [])
    return new_manifest(tool["name"], "tool", tool.get("description") or tool.get("title") or "",
                        schema, publisher, **fields)


def default_gate(findings: List[Finding]) -> bool:
    """Admite se nao ha erro e ha no maximo um aviso de instrucao suspeita."""
    if any(f.severity == "error" for f in findings):
        return False
    return sum(f.rule == "SELO004" for f in findings) < 2


@dataclass
class BridgeReport:
    admitted: List[str] = field(default_factory=list)
    rejected: Dict[str, List[str]] = field(default_factory=dict)
    warnings: Dict[str, List[str]] = field(default_factory=dict)


class McpBridge:
    """Admite as tools de um servidor MCP no host SELO.

    `publish(manifest, handler)` e fornecido pelo administrador (no laboratorio:
    `lambda m, h: world.publish(host, publisher_id, m, h)`) e devolve o hash admitido."""

    def __init__(self, client: McpStdioClient, publisher: str,
                 publish: Callable[[Dict[str, Any], Callable], str],
                 gate: Callable[[List[Finding]], bool] = default_gate,
                 overrides: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.client, self.publisher, self.publish = client, publisher, publish
        self.gate, self.overrides = gate, overrides

    def _handler(self, name: str):
        def handler(args: Dict[str, Any]) -> Dict[str, Any]:
            result = self.client.call_tool(name, args)
            return {"out": result_to_text(result), "error": "tool_error" if result.get("isError") else None}
        return handler

    def admit_all(self) -> BridgeReport:
        report = BridgeReport()
        manifests = [tool_to_manifest(t, self.publisher, self.overrides) for t in self.client.list_tools()]
        findings = lint_manifests(manifests)
        for m in manifests:
            mine = [f for f in findings if f.capability == m["name"]]
            if not self.gate(mine):
                report.rejected[m["name"]] = [str(f) for f in mine]
                continue
            self.publish(m, self._handler(m["name"]))
            report.admitted.append(m["name"])
            if mine:
                report.warnings[m["name"]] = [str(f) for f in mine]
        return report
