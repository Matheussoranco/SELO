"""Ticket #7: rotacao de chaves, revogacao e falha fechada do Agent Card."""

import copy
import json
import subprocess
import sys
import unittest
import urllib.request

from selo import envelope
from selo.card import WELL_KNOWN, verify_card
from selo.errors import SeloError
from selo.identity import ROTATION_GRACE, Identity
from tests.e2e import World
from tests.e2e import send_message as e2e_message
from tests.harness import FakeClock
from tests.inproc import InWorld, error_code, send_message


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


def _card(url):
    with urllib.request.urlopen(url + WELL_KNOWN, timeout=10) as r:
        return json.loads(r.read())


class RotationTest(unittest.TestCase):
    def test_new_key_accepted_old_key_rejected_after_window(self):
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            self.assertNotIn("error", a.send(b, "antes"))
            old = Identity.from_secret(copy.deepcopy(a.sc.identity.to_secret()))
            a.sc.rotate_keys()
            w.clock.advance(1)
            card = _card(a.url)
            kel = card["capabilities"]["extensions"][0]["params"]["kel"]
            self.assertEqual([s["body"]["t"] for s in kel], ["inception", "rotation"])

            resp = a.send(b, "com a chave nova")
            self.assertNotIn("error", resp, resp)
            self.assertEqual(
                b.agent.received[-1]["sender"], a.agent_id
            )  # mesmo agent_id

            b_info, _ = a.sc.peers.get(b.url)

            def old_key_envelope():
                return envelope.seal(
                    sender=old,
                    sender_card_url=a.url,
                    recipient=b_info,
                    body={"rpc": send_message("chave velha")},
                    t="req",
                    now=w.clock(),
                )

            status, _ = _post(b.url + "/selo/v1/envelope", old_key_envelope())
            self.assertEqual(status, 200)  # dentro da janela de rotacao
            w.clock.advance(ROTATION_GRACE + 1)
            status, body = _post(b.url + "/selo/v1/envelope", old_key_envelope())
            self.assertEqual((status, body["error"]), (400, "bad_signature"))
            self.assertNotIn("error", a.send(b, "depois da janela"))
            self.assertNotIn("error", b.send(a, "b fala com a chave nova de a"))

    def test_peer_sending_to_old_key_retries_after_window(self):
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            self.assertNotIn("error", a.send(b, "fixa o Card de b"))
            old_card = copy.deepcopy(b.sc.card())
            b.sc.rotate_keys()
            w.clock.advance(
                ROTATION_GRACE + 5
            )  # o Card em cache de a ainda tem a chave velha
            a.sc.peers._cache.clear()
            a.sc.peers._cache[b.sc.base_url] = (old_card, w.clock())
            resp = a.send(b, "para a chave velha")
            self.assertNotIn("error", resp, resp)

    def test_tampered_rotation_chain_rejected(self):
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            a.sc.rotate_keys()
            real = a.sc.card()
            bad = copy.deepcopy(real)
            p = bad["capabilities"]["extensions"][0]["params"]
            p["kel"][1]["body"]["agree_pub"] = p["kel"][0]["body"]["agree_pub"]
            with self.assertRaises(SeloError) as cm:
                verify_card(bad, now=w.clock())
            self.assertEqual(cm.exception.code, "bad_kel")
            a.sc._card = bad
            a.sc.card = lambda: bad  # o sidecar passa a servir a cadeia adulterada
            self.assertEqual(error_code(b.send(a, "x")), "bad_kel")

    def test_kel_fork_rejected_after_pinning(self):
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            clone = Identity.from_secret(copy.deepcopy(a.sc.identity.to_secret()))
            a.sc.rotate_keys()
            self.assertNotIn("error", b.send(a, "fixa seq 1"))
            clone.rotate(int(w.clock()))  # outra rotacao a partir do mesmo seq 0
            a.sc.identity = clone
            a.sc._card = None
            w.clock.advance(31)  # expira o cache do Card em b
            self.assertEqual(error_code(b.send(a, "bifurcada")), "kel_fork")


class FreshnessTest(unittest.TestCase):
    def test_expired_card_drops_connection(self):
        with InWorld() as w:
            late = FakeClock(w.clock() - 2 * 3600)
            a = w.node("a", clock=late, cfg={"card": {"validity": 3600}})
            b = w.node("b")
            self.assertEqual(error_code(b.send(a, "x")), "card_stale")

    def test_card_older_than_max_age_rejected_and_configurable(self):
        with InWorld() as w:
            a = w.node("a")
            a.sc.card()  # Card emitido agora
            w.clock.advance(100)  # relogios sincronizados; o Card envelhece 100 s
            strict = w.node("strict", cfg={"card": {"max_card_age": 60}})
            relaxed = w.node("relaxed")
            self.assertEqual(error_code(strict.send(a, "x")), "card_stale")
            self.assertNotIn("error", relaxed.send(a, "x"))

    def test_revoked_identity_rejected(self):
        with InWorld() as w:
            a, b = w.node("a"), w.node("b")
            self.assertNotIn("error", b.send(a, "antes"))
            a.sc.revoke_identity()
            w.clock.advance(31)
            self.assertEqual(error_code(b.send(a, "depois")), "identity_revoked")
            self.assertEqual(error_code(a.send(b, "depois")), "identity_revoked")

    def test_desynchronized_clock_fails(self):
        with InWorld() as w:
            ahead = FakeClock(w.clock() + 600)
            a = w.node("a", clock=ahead)
            b = w.node("b")
            code = error_code(a.send(b, "do futuro"))
            self.assertIn(code, ("invalid_lifetime", "card_stale"))
            self.assertEqual(b.agent.received, [])


class ProcessRotationTest(unittest.TestCase):
    def test_cli_rotation_and_clock_offset_harness(self):
        with World() as w:
            a, b = w.node("a"), w.node("b")
            self.assertNotIn("error", a.client.call(b.url, e2e_message("antes")))
            b.stop_sidecar()
            out = subprocess.run(
                [sys.executable, "-m", "selo", "rotate", "--config", b.config_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            ).stdout
            self.assertEqual(json.loads(out.strip().splitlines()[-1])["kel_len"], 2)
            b.start()
            resp = a.client.call(b.url, e2e_message("depois da rotacao"))
            self.assertNotIn("error", resp, resp)
            self.assertEqual(b.received()[-1]["sender"], a.agent_id)
            # relogio injetavel do harness: sidecar adiantado 10 minutos
            c = w.node("c", cfg={"clock_offset": 600})
            self.assertIn("error", c.client.call(b.url, e2e_message("adiantado")))


if __name__ == "__main__":
    unittest.main()


class CacheTest(unittest.TestCase):
    def test_rejected_card_is_not_cached(self):
        """Um par cujo Card foi recusado volta a ser aceito assim que corrige o problema."""
        with InWorld() as w:
            late = FakeClock(w.clock() - 3 * 3600)
            a = w.node("a", clock=late, cfg={"card": {"validity": 3600}})
            b = w.node("b")
            self.assertEqual(error_code(b.send(a, "x")), "card_stale")
            a.clock.t = w.clock()  # relogio corrigido
            a.sc._card = None
            self.assertNotIn("error", b.send(a, "logo em seguida"))
