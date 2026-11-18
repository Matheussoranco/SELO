"""Ticket #10: gancho de politica no nucleo."""

import dataclasses
import unittest

from selo.errors import SeloError
from selo.policy import NullHook, load_hook
from tests import policies
from tests.inproc import InWorld, error_code


class PolicyHookTest(unittest.TestCase):
    def setUp(self):
        policies.EVENTS.clear()

    def test_hook_can_refuse_with_defined_error(self):
        with InWorld() as w:
            b = w.node("b", cfg={"policy": "tests.policies:deny_forbidden"})
            a = w.node("a")
            resp = a.send(b, "isto e proibido")
            self.assertEqual(resp["error"]["code"], -32093)
            self.assertEqual(resp["error"]["message"], "policy_denied")
            self.assertEqual(resp["error"]["data"]["detail"], "palavra proibida")
            self.assertEqual(b.agent.received, [])  # nao chegou ao agente
            self.assertNotIn("error", a.send(b, "isto e permitido"))
            stages = [(e.direction, e.stage) for e in policies.EVENTS]
            self.assertIn(("inbound", "request"), stages)
            self.assertIn(("inbound", "response"), stages)
            ev = policies.EVENTS[0]
            self.assertEqual(ev.peer_id, a.agent_id)
            self.assertIsNone(ev.peer_org)
            self.assertEqual(ev.method, "SendMessage")

    def test_outbound_hook(self):
        with InWorld() as w:
            a = w.node("a", cfg={"policy": "tests.policies:deny_outbound_to_all"})
            b = w.node("b")
            self.assertEqual(error_code(a.send(b, "x")), "policy_denied")
            self.assertEqual(b.agent.received, [])

    def test_without_hook_nothing_changes(self):
        self.assertIsInstance(load_hook(None), NullHook)
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            self.assertNotIn("error", a.send(b, "proibido, mas sem gancho"))

    def test_event_carries_no_keys_and_is_a_copy(self):
        fields = {
            f.name
            for f in dataclasses.fields(__import__("selo.policy").policy.PolicyEvent)
        }
        self.assertEqual(
            fields, {"direction", "stage", "peer_id", "peer_org", "method", "rpc"}
        )
        with InWorld() as w:
            b = w.node("b", cfg={"policy": "tests.policies:mutate"})
            a = w.node("a")
            a.send(b, "original")
            self.assertEqual(b.agent.received[-1]["text"], "original")
        with InWorld() as w:
            b = w.node("b", cfg={"policy": "tests.policies:record"})
            a = w.node("a")
            a.send(b, "x")
            for ev in policies.EVENTS:
                for value in vars(ev).values():
                    self.assertNotIsInstance(value, type(b.sc))
                    self.assertNotIn("PrivateKey", type(value).__name__)

    def test_hook_error_fails_closed(self):
        with InWorld() as w:
            b = w.node("b", cfg={"policy": "tests.policies:crash"})
            a = w.node("a")
            resp = a.send(b, "x")
            self.assertEqual(resp["error"]["message"], "policy_denied")
            self.assertIn("RuntimeError", resp["error"]["data"]["detail"])

    def test_bad_spec(self):
        for spec in (
            "sem_dois_pontos",
            "modulo_inexistente_xyz:f",
            "tests.policies:nao_existe",
        ):
            with self.subTest(spec=spec), self.assertRaises(SeloError):
                load_hook(spec)


if __name__ == "__main__":
    unittest.main()
