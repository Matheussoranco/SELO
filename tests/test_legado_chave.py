"""Testes do protocolo Chave-Organizacao v3."""

import json
import time
import unittest
from cripto_agent.legado.chave_protocol import (
    AgentKeys, OrgEscrowKeys, Capability, SecureAgent, EnvelopeError,
    encrypt_message, decrypt_message, org_decrypt_message,
)

ORG = "demo-org"


def make_keys(agent_id):
    return AgentKeys.generate(agent_id)


def make_org(org=ORG):
    return OrgEscrowKeys.generate(org)


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.org = make_org(ORG)
        self.a = make_keys("agent-a")
        self.b = make_keys("agent-b")
        self.identities = {"agent-a": self.a.identity_public_pem,
                           "agent-b": self.b.identity_public_pem}
        self.agreements = {"agent-a": self.a.agreement_public_pem,
                           "agent-b": self.b.agreement_public_pem}

    def test_encrypt_decrypt_recipient_path(self):
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "ola"})
        payload, via_org = decrypt_message(
            envelope, self.b, org_private_pem=self.org.private_pem,
            expected_org=ORG,
            sender_identity_public_pem=self.a.identity_public_pem)
        self.assertFalse(via_org)
        self.assertEqual(payload["arguments"], {"text": "ola"})
        self.assertEqual(payload["sender"], "agent-a")
        self.assertEqual(payload["recipient"], "agent-b")

    def test_org_decrypt_recovers_payload(self):
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "skill", "name": "text.stats"}, {"text": "x y z"})
        payload = org_decrypt_message(
            envelope, self.org.private_pem, self.a.identity_public_pem,
            expected_org=ORG)
        self.assertEqual(payload["arguments"], {"text": "x y z"})
        self.assertEqual(payload["sender"], "agent-a")

    def test_via_org_flag_when_recipient_cannot_unwrap(self):
        # Outro agente cuja chave de acordo nao combina com a encapsulacao
        # feita para agent-b, entao nao consegue recuperar K sozinho.
        outro = make_keys("agent-c")
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "segredo"})
        with self.assertRaises(EnvelopeError) as ctx:
            decrypt_message(envelope, outro, org_private_pem=None,
                            expected_org=ORG,
                            sender_identity_public_pem=self.a.identity_public_pem)
        self.assertEqual(ctx.exception.code, "cannot_unwrap")

        # A empresa recupera via escrow (via_org = True).
        payload, via_org = decrypt_message(
            envelope, outro, org_private_pem=self.org.private_pem,
            expected_org=ORG,
            sender_identity_public_pem=self.a.identity_public_pem)
        self.assertTrue(via_org)
        self.assertEqual(payload["arguments"], {"text": "segredo"})

    def test_tampered_ciphertext_rejected(self):
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "ok"})
        envelope["ciphertext"] = "AAAA"
        with self.assertRaises(EnvelopeError) as ctx:
            decrypt_message(envelope, self.b,
                            org_private_pem=self.org.private_pem,
                            expected_org=ORG,
                            sender_identity_public_pem=self.a.identity_public_pem)
        # A assinatura cobre o cabeceario inteiro (incluindo ciphertext), então
        # adulterar o ciphertext invalida a assinatura antes mesmo da cifragem.
        self.assertEqual(ctx.exception.code, "bad_signature")

    def test_wrong_sender_key_rejected(self):
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "ok"})
        with self.assertRaises(EnvelopeError) as ctx:
            decrypt_message(envelope, self.b,
                            org_private_pem=self.org.private_pem,
                            expected_org=ORG,
                            sender_identity_public_pem=self.b.identity_public_pem)
        self.assertEqual(ctx.exception.code, "bad_signature")

    def test_org_mismatch_rejected(self):
        envelope = encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "ok"})
        with self.assertRaises(EnvelopeError) as ctx:
            decrypt_message(envelope, self.b,
                            org_private_pem=self.org.private_pem,
                            expected_org="outra-org",
                            sender_identity_public_pem=self.a.identity_public_pem)
        self.assertEqual(ctx.exception.code, "org_mismatch")


class SecureAgentTests(unittest.TestCase):
    def setUp(self):
        self.org = make_org(ORG)
        self.a = make_keys("agent-a")
        self.b = make_keys("agent-b")
        self.identities = {"agent-a": self.a.identity_public_pem,
                           "agent-b": self.b.identity_public_pem}
        self.agreements = {"agent-a": self.a.agreement_public_pem,
                           "agent-b": self.b.agreement_public_pem}
        self.b_agent = SecureAgent(
            ORG, "agent-b", self.b, self.org.public_pem, self.org.private_pem,
            self.identities, self.agreements,
            {("agent-a", "tool", "echo"), ("agent-a", "skill", "text.stats")},
            ":memory:",
        )
        self.b_agent.register(Capability("tool", "echo", "echo", lambda a: {"text": a["text"]}))
        self.b_agent.register(Capability("skill", "text.stats", "stats",
                                         lambda a: {"words": len(a["text"].split()),
                                                    "chars": len(a["text"])}))

    def _envelope_from_a(self, capability, arguments):
        return encrypt_message(
            ORG, "agent-a", "agent-b", self.a,
            self.b.agreement_public_pem, self.org.public_pem,
            capability, arguments)

    def test_dispatch_tool_and_skill(self):
        env = self._envelope_from_a({"kind": "tool", "name": "echo"},
                                    {"text": "ola"})
        resp = self.b_agent.dispatch(env)
        self.assertEqual(resp["result"], {"text": "ola"})
        self.assertFalse(resp["decrypted_via_org"])

        env2 = self._envelope_from_a({"kind": "skill", "name": "text.stats"},
                                     {"text": "uma frase aqui"})
        resp2 = self.b_agent.dispatch(env2)
        self.assertEqual(resp2["result"], {"words": 3, "chars": 14})

    def test_forbidden_capability_rejected(self):
        env = self._envelope_from_a({"kind": "tool", "name": "shell"},
                                    {"cmd": "id"})
        with self.assertRaises(EnvelopeError) as ctx:
            self.b_agent.dispatch(env)
        self.assertEqual(ctx.exception.code, "forbidden")

    def test_unknown_sender_rejected(self):
        outro = make_keys("intruso")
        env = encrypt_message(
            ORG, "intruso", "agent-b", outro,
            self.b.agreement_public_pem, self.org.public_pem,
            {"kind": "tool", "name": "echo"}, {"text": "x"})
        with self.assertRaises(EnvelopeError) as ctx:
            self.b_agent.dispatch(env)
        self.assertEqual(ctx.exception.code, "unknown_sender")

    def test_replay_persistent_rejected(self):
        env = self._envelope_from_a({"kind": "tool", "name": "echo"},
                                    {"text": "unico"})
        self.b_agent.dispatch(env)
        with self.assertRaises(EnvelopeError) as ctx:
            self.b_agent.dispatch(env)
        self.assertEqual(ctx.exception.code, "replay")

    def test_catalog_filters_by_permission(self):
        cat = self.b_agent.catalog("agent-a")
        names = {(c["kind"], c["name"]) for c in cat["capabilities"]}
        self.assertIn(("tool", "echo"), names)
        self.assertIn(("skill", "text.stats"), names)
        self.assertNotIn(("tool", "shell"), names)

    def test_org_decrypt_on_agent(self):
        env = self._envelope_from_a({"kind": "tool", "name": "echo"},
                                    {"text": "escrow"})
        payload = self.b_agent.org_decrypt(env)
        self.assertEqual(payload["arguments"], {"text": "escrow"})


if __name__ == "__main__":
    unittest.main()
