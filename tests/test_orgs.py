"""Tickets #13 (federacao explicita) e #14 (escrow organizacional opcional)."""

import json
import os
import unittest

from selo.errors import SeloError
from selo.org import AuditLog, Organization
from tests.inproc import InWorld, error_code


class OrgEnv:
    """Organizacoes em processo, cada uma com o servidor da lista de revogacao."""

    def __init__(self, w: InWorld) -> None:
        self.w = w
        self.servers = []

    def org(self, name: str, escrow: bool = False) -> Organization:
        org = Organization.create(name, escrow_enabled=escrow)
        srv = org.serve(clock=self.w.clock)
        org.revocations_url = f"http://127.0.0.1:{srv.port}/revocations"
        org.server = srv
        self.servers.append(srv)
        return org

    def close(self) -> None:
        for s in self.servers:
            try:
                s.stop()
            except Exception:
                pass


class FederationTest(unittest.TestCase):
    def setUp(self):
        self.w = InWorld().__enter__()
        self.env = OrgEnv(self.w)
        self.acme, self.globex = self.env.org("acme"), self.env.org("globex")
        self.a1, self.a2 = self.w.node("a1"), self.w.node("a2")
        self.b1, self.loner = self.w.node("b1"), self.w.node("loner")
        self.a1.join(self.acme)
        self.a2.join(self.acme)
        self.b1.join(self.globex)

    def tearDown(self):
        self.env.close()
        self.w.__exit__(None, None, None)

    def test_same_org_members_talk(self):
        self.assertNotIn("error", self.a1.send(self.a2, "dentro da acme"))
        self.assertEqual(self.a2.agent.received[-1]["org"], "acme")

    def test_other_org_rejected_without_anchor(self):
        self.assertEqual(error_code(self.a1.send(self.b1, "x")), "peer_untrusted")
        # mesmo que um lado confie, o receptor sem ancora recusa
        self.a1.restart({"trust": {"orgs": [self.globex.anchor_entry()]}})
        self.assertEqual(error_code(self.a1.send(self.b1, "x")), "peer_untrusted")
        self.assertEqual(self.b1.agent.received, [])

    def test_anchors_on_both_sides_then_removed(self):
        self.a1.restart({"trust": {"orgs": [self.globex.anchor_entry()]}})
        self.b1.restart({"trust": {"orgs": [self.acme.anchor_entry()]}})
        self.assertNotIn("error", self.a1.send(self.b1, "federado"))
        self.assertEqual(self.b1.agent.received[-1]["org"], "acme")
        self.assertNotIn("error", self.b1.send(self.a1, "de volta"))
        self.b1.restart({"trust": {"orgs": []}})
        self.assertEqual(error_code(self.a1.send(self.b1, "x")), "peer_untrusted")

    def test_unattested_peer_and_member_policy(self):
        self.assertEqual(error_code(self.loner.send(self.a1, "x")), "peer_untrusted")
        self.a1.restart({"trust": {"allow_unattested": True}})
        self.assertNotIn("error", self.loner.send(self.a1, "permitido explicitamente"))
        self.assertEqual(self.a1.agent.received[-1]["org"], "")

    def test_revocation_respected_and_fail_closed(self):
        self.a1.restart({"trust": {"orgs": [self.globex.anchor_entry()]}})
        self.b1.restart({"trust": {"orgs": [self.acme.anchor_entry()]}})
        self.assertNotIn("error", self.a1.send(self.b1, "antes"))
        self.acme.revoke(self.a1.agent_id)
        self.w.clock.advance(3601)  # a lista em cache vence; b1 busca a nova
        self.assertEqual(error_code(self.a1.send(self.b1, "depois")), "peer_revoked")
        self.assertEqual(
            error_code(self.a2.send(self.a1, "membro revogado")), "peer_revoked"
        )
        # servidor da lista fora do ar: falha fechada
        self.globex.server.stop()
        self.w.clock.advance(3601)
        self.assertEqual(error_code(self.b1.send(self.a2, "x")), "peer_untrusted")
        self.assertEqual(error_code(self.a1.send(self.b1, "x")), "revocations_stale")

    def test_forged_attestation_ignored_or_rejected(self):
        mallory = Organization.create("acme")  # mesmo nome, outra ancora
        self.loner.join(mallory)
        # a assinatura nao confere com a ancora "acme" configurada: recusada
        self.assertEqual(
            error_code(self.loner.send(self.a1, "sou da acme")), "bad_org_doc"
        )
        self.assertEqual(error_code(self.a1.send(self.loner, "x")), "bad_org_doc")
        self.assertEqual(self.a1.agent.received, [])
        stolen = self.acme.attest(
            self.a2.agent_id, self.w.clock()
        )  # atestacao de outro agente
        self.loner.restart({"org": None, "trust": {"orgs": []}})
        self.loner.sc.orgs = None
        self.loner.sc._attestations = lambda: [stolen]
        self.loner.sc._card = None
        self.assertEqual(error_code(self.a2.send(self.loner, "x")), "bad_attestation")


class EscrowTest(unittest.TestCase):
    def setUp(self):
        self.w = InWorld().__enter__()
        self.env = OrgEnv(self.w)
        self.acme = self.env.org("acme", escrow=True)
        self.globex = self.env.org("globex")

    def tearDown(self):
        self.env.close()
        self.w.__exit__(None, None, None)

    def test_missing_capsule_rejected_when_required(self):
        old_descriptor = Organization(
            self.acme.name,
            self.acme.master,
            self.acme.revocations_url,
            escrow_enabled=False,
        ).descriptor(self.w.clock())
        a1, a2 = self.w.node("a1"), self.w.node("a2")
        a1.join(
            self.acme, descriptor=old_descriptor
        )  # a1 nao sabe que o escrow foi ligado
        a2.join(self.acme)
        self.assertEqual(error_code(a1.send(a2, "sem capsula")), "escrow_required")
        self.assertEqual(a2.agent.received, [])

    def test_master_shares_rebuild_escrow_key(self):
        parts = self.acme.master_shares(2, 3)
        rebuilt = Organization(
            "acme", Organization.master_from_shares(parts[1:]), escrow_enabled=True
        )
        self.assertEqual(rebuilt.anchor_pub, self.acme.anchor_pub)
        with self.assertRaises(Exception):
            Organization.master_from_shares([])

    def test_audit_log_roundtrip(self):
        log = AuditLog()
        log.append({"auditor": "a", "reason": "r", "digest": "d", "t": 1})
        log.append({"auditor": "b", "reason": "r", "digest": "e", "t": 2})
        path = os.path.join(self.w.tmp, "audit.jsonl")
        log.save(path)
        self.assertTrue(AuditLog.load(path).verify())


if __name__ == "__main__":
    unittest.main()


class OrgCliTest(unittest.TestCase):
    def test_cli_init_attest_revoke_shares(self):
        import subprocess
        import sys
        import tempfile

        d = tempfile.mkdtemp(prefix="selo-orgcli-")
        env = dict(os.environ, SELO_KEY_PASSWORD="senha-org")

        def run(*args):
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "selo",
                    "org",
                    *args,
                    "--dir",
                    d,
                    "--keystore",
                    "file",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)

        out = run(
            "init",
            "--name",
            "acme",
            "--revocations-url",
            "http://127.0.0.1:1/revocations",
            "--escrow",
        )
        self.assertEqual(out["anchor"]["name"], "acme")
        self.assertTrue(out["descriptor"]["body"]["escrow"]["enabled"])
        self.assertNotIn(b"master", open(os.path.join(d, "org.json"), "rb").read())
        att = run("attest", "--agent-id", "selo:abc")
        self.assertEqual(att["body"]["agent_id"], "selo:abc")
        rev = run("revoke", "--agent-id", "selo:abc")
        self.assertEqual(rev["body"]["revoked"], ["selo:abc"])
        self.assertEqual(len(run("shares", "--threshold", "2", "--count", "3")), 3)
