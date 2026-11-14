"""Seam principal, ticket #5: SendMessage entre dois sidecars na mesma maquina, sem organizacao."""

import json
import os
import unittest
import urllib.request
from multiprocessing.connection import Client

from selo import EXTENSION_URI
from selo.card import WELL_KNOWN, verify_card
from selo.local import LocalClient
from selo.errors import SeloError
from tests.e2e import World, send_message


def _post(url, body):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class SkeletonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World().__enter__()
        cls.a = cls.w.node("alice")
        cls.b = cls.w.node("bob", proxied=True)

    @classmethod
    def tearDownClass(cls):
        cls.w.__exit__(None, None, None)

    def test_send_message_arrives_only_at_destination(self):
        secret = "segredo-7f3a-nao-pode-vazar"
        resp = self.a.client.call(self.b.url, send_message(secret))
        self.assertNotIn("error", resp, resp)
        task = resp["result"]["task"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")
        self.assertEqual(task["artifacts"][0]["parts"][0]["text"], f"eco: {secret}")
        got = [r for r in self.b.received() if r["text"] == secret]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["sender"], self.a.agent_id)  # remetente autenticado
        self.assertEqual(got[0]["org"], "")  # sem organizacao
        self.assertTrue(self.b.proxy.find("/selo/v1/envelope"))
        self.assertFalse(self.b.proxy.plaintext_seen(secret))
        self.assertFalse(self.b.proxy.plaintext_seen("eco: "))

    def test_agent_card_is_served_and_signed(self):
        with urllib.request.urlopen(self.b.url + WELL_KNOWN, timeout=10) as r:
            card = json.loads(r.read())
        import time

        info = verify_card(card, now=time.time())
        self.assertEqual(info.agent_id, self.b.agent_id)
        ext = card["capabilities"]["extensions"][0]
        self.assertEqual(ext["uri"], EXTENSION_URI)
        self.assertTrue(ext["required"])
        self.assertEqual(ext["params"]["attestations"], [])
        tampered = json.loads(json.dumps(card))
        tampered["name"] = "outro"
        with self.assertRaises(SeloError):
            verify_card(tampered, now=time.time())

    def test_works_without_org_certificate_or_seed(self):
        self.assertNotIn("org", self.a.cfg)
        self.assertIsNone(self.a.client.whoami()["org"])

    def test_agent_cannot_read_private_keys(self):
        who = self.a.client.whoami()
        self.assertEqual(set(who), {"agent_id", "public_url", "org"})
        reply = self.a.client._roundtrip({"op": "keys"})
        self.assertIn("error", reply)
        key_dir = os.path.join(self.a.state_dir, "keys")
        for name in os.listdir(key_dir):
            with open(os.path.join(key_dir, name), "rb") as fh:
                raw = fh.read()
            self.assertNotIn(b'"sig"', raw)  # blob protegido, nao JSON em claro
            self.assertNotIn(b"PRIVATE KEY", raw)

    def test_local_channel_requires_the_key(self):
        info = self.a.info["local"]
        family = "AF_PIPE" if info["mode"] == "pipe" else "AF_UNIX"
        with self.assertRaises(Exception):
            Client(info["address"], family=family, authkey=b"x" * 32)
        # e o canal continua funcionando para quem tem a chave
        self.assertEqual(self.a.client.whoami()["agent_id"], self.a.agent_id)

    def test_replay_tamper_and_wrong_recipient_rejected(self):
        self.a.client.call(self.b.url, send_message("para gravar"))
        ex = self.b.proxy.find("/selo/v1/envelope")[-1]
        status, body = self.b.proxy.replay(ex)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"], "replay")

        self.b.proxy.tamper_next()
        resp = self.a.client.call(self.b.url, send_message("adulterada"))
        self.assertIn("error", resp)
        self.assertNotIn("adulterada", [r["text"] for r in self.b.received()])

        env = json.loads(ex.body)
        status, body = _post(
            self.a.url + "/selo/v1/envelope", env
        )  # envelope de B entregue a A
        self.assertEqual((status, body["error"]), (400, "wrong_recipient"))

    def test_plaintext_a2a_is_refused(self):
        status, body = _post(self.b.url + "/", send_message("em claro"))
        self.assertEqual(status, 200)
        self.assertEqual(body["error"]["code"], -32090)
        self.assertEqual(body["error"]["data"]["extension"], EXTENSION_URI)

    def test_peer_card_through_local_channel(self):
        card = self.a.client.card(self.b.url)
        self.assertEqual(
            card["capabilities"]["extensions"][0]["params"]["agent_id"], self.b.agent_id
        )


class LocalHttpModeTest(unittest.TestCase):
    def test_http_local_mode_requires_token(self):
        with World() as w:
            a = w.node("carol", cfg={"local": {"mode": "http"}})
            b = w.node("dave")
            self.assertEqual(a.info["local"]["mode"], "http")
            resp = a.client.call(b.url, send_message("via http local"))
            self.assertEqual(
                resp["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED"
            )
            url = a.info["local"]["url"] + "/whoami"
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(url, timeout=10)
            self.assertEqual(cm.exception.code, 401)
            bad = LocalClient(info=a.info["local"])
            bad._token = "errado"
            with self.assertRaises(SeloError):
                bad.call(b.url, send_message("x"))


if __name__ == "__main__":
    unittest.main()
