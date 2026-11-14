import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from selo_v0 import Agent, RemoteError, Session, SeloError
from selo_v0.sandbox import World
from selo_v0.util import check_id


class TokenReservations(unittest.TestCase):
    def setUp(self):
        self.world = World().standard()
        self.addCleanup(self.world.close)
        self.client = self.world.agents["assistant"]
        self.host = self.world.agents["erp"]
        self.cap = "erp.get_balance"
        self.token = self.host.mint(self.cap, [{"holder": "assistant"}, {"max_uses": 1}])

    def call(self, token=None):
        return self.client.call("erp", self.cap, {"account": "matriz"},
                                token or self.token, Session(), self.world.send)

    def reopen(self, path):
        old = self.host
        host = Agent(agent_id=old.id, org=old.org, sig_sk=old.sig_sk, cert=old.cert,
                     keys=old.keys, directory=old.directory, entry_provider=old.entry_provider,
                     clock=old.clock, revoked=old.revoked, token_root=old.token_root,
                     manifests=old.manifests, db=str(path))
        host.caps = old.caps.copy()
        old.close()
        self.host = self.world.agents["erp"] = host

    def test_limit_survives_reopening_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sqlite"
            self.reopen(path)
            self.call()
            self.reopen(path)
            with self.assertRaisesRegex(RemoteError, "caveat_failed"):
                self.call()
            self.assertEqual(self.host.token_uses(), {self.token.ident: 1})
            self.host.close()

    def test_concurrent_calls_reserve_before_handler(self):
        entered, release = threading.Event(), threading.Event()
        original = self.host.caps[self.cap].handler

        def handler(args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test handler timed out")
            return original(args)

        self.host.caps[self.cap].handler = handler
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.call)
            try:
                self.assertTrue(entered.wait(5))
                second = pool.submit(self.call)
                with self.assertRaisesRegex(RemoteError, "caveat_failed"):
                    second.result(timeout=5)
            finally:
                release.set()
            self.assertIn("balance_cents", first.result(timeout=5))
        self.assertEqual(self.host.token_uses(), {self.token.ident: 1})

    def test_failed_handler_still_consumes_reservation(self):
        def handler(args):
            raise ValueError("external effect may already have happened")

        self.host.caps[self.cap].handler = handler
        with self.assertRaisesRegex(RemoteError, "invalid_arguments"):
            self.call()
        with self.assertRaisesRegex(RemoteError, "caveat_failed"):
            self.call()
        self.assertEqual(self.host.token_uses(), {self.token.ident: 1})

    def test_denied_token_does_not_consume_reservation(self):
        with self.assertRaisesRegex(RemoteError, "caveat_failed"):
            self.call(self.token.attenuate({"holder": "web"}))
        self.assertEqual(self.host.token_uses(), {})
        self.call()

    def test_generator_keeps_all_caveats(self):
        caveats = ({"holder": "assistant"}, {"max_uses": 0})
        token = self.host.mint(self.cap, (c for c in caveats))
        self.assertEqual(token.caveats, caveats)
        with self.assertRaisesRegex(RemoteError, "caveat_failed"):
            self.call(token)

    def test_malformed_taint_caveat_fails_closed(self):
        with self.assertRaisesRegex(RemoteError, "caveat_failed"):
            self.call(self.token.attenuate({"forbid_taint": [{}]}))
        self.assertEqual(self.host.token_uses(), {})

    def test_identifier_rejects_trailing_newline(self):
        with self.assertRaises(SeloError):
            check_id("assistant\n")
