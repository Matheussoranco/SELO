"""SELO sobre HTTP real (loopback): diretorio da organizacao, dois agentes servidores e um cliente."""

import http.client
import json
import time
import unittest

from cripto_agent.selo import RemoteError, Session
from cripto_agent.selo.sandbox import World
from cripto_agent.selo.transport import (OrgClient, fetch_catalog, http_send, serve_agent,
                                         serve_org)

MAL = "https://noticias.example/maliciosa"


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.w = World(clock=time.time).standard()
        self.addCleanup(self.w.close)
        self.servers = [serve_org(self.w.org)]
        self.org_srv = self.servers[0]
        for name in ("erp", "web"):
            srv = serve_agent(self.w.agents[name])
            self.servers.append(srv)
            self.w.org.urls[name] = srv.url
        self.addCleanup(lambda: [s.stop() for s in self.servers])

        # O cliente descobre tudo pela rede, ancorado apenas nos parametros publicos da organizacao.
        params = OrgClient.bootstrap_params(self.org_srv.url)
        client = OrgClient(self.org_srv.url, params)
        a = self.w.agents["assistant"]
        a.directory, a.entry_provider = client.directory, client.entry
        a.manifests.resolver = client.manifest_bundle
        self.a, self.client = a, client
        self.alice = self.w.principals["alice"]
        self.s = Session()
        self.s.observe(self.alice.instruct("Pague INV-1"))

    def call(self, host, cap, args, token, session=None):
        return self.a.call(host, cap, args, token, session or self.s, http_send)

    def test_call_over_http(self):
        tok = self.w.agents["erp"].mint("erp.get_balance", [{"holder": "assistant"}])
        self.assertEqual(self.call("erp", "erp.get_balance", {"account": "matriz"}, tok),
                         {"balance_cents": 12500000})

    def test_injection_is_blocked_over_http(self):
        fetch = self.w.agents["web"].mint("web.fetch", [{"holder": "assistant"}])
        pay = self.w.agents["erp"].mint("erp.pay_invoice", [{"holder": "assistant"}])
        self.assertIn("IGNORE", self.call("web", "web.fetch", {"url": MAL}, fetch)["text"])
        with self.assertRaises(RemoteError) as cm:
            self.call("erp", "erp.pay_invoice", {"invoice": "INV-999", "amount_cents": 9}, pay)
        self.assertEqual(cm.exception.code, "tainted_context")

    def test_catalog_and_manifest_verification_over_http(self):
        bundle = fetch_catalog(self.w.org.urls["web"])[0]
        self.assertEqual(self.a.learn(bundle)["name"], "web.fetch")

    def test_garbage_and_replay_get_generic_rejection(self):
        url = self.w.org.urls["erp"].split("//")[1]
        host, port = url.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=5)
        conn.request("POST", "/selo/v1/inbox", b'{"not":"an envelope"}',
                     {"Content-Type": "application/json"})
        r = conn.getresponse()
        self.assertEqual((r.status, json.loads(r.read())), (400, {"error": "rejected"}))
        conn.close()

    def test_revocation_list_is_signed_and_enforced(self):
        self.w.org.revoke(self.w.org.agents["assistant"]["serial"])
        self.assertIn(self.w.org.agents["assistant"]["serial"], self.client.revoked())


if __name__ == "__main__":
    unittest.main()
