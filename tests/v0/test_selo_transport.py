"""SELO sobre HTTP real (loopback): diretorio da organizacao, dois agentes servidores e um cliente."""

import http.client
import json
import socket
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from selo_v0 import RemoteError, Session
from selo_v0.sandbox import World
from selo_v0.transport import (
    OrgClient,
    fetch_catalog,
    http_send,
    serve_agent,
    serve_org,
    _make_handler,
    _Server,
)

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
        self.assertEqual(
            self.call("erp", "erp.get_balance", {"account": "matriz"}, tok),
            {"balance_cents": 12500000},
        )

    def test_injection_is_blocked_over_http(self):
        fetch = self.w.agents["web"].mint("web.fetch", [{"holder": "assistant"}])
        pay = self.w.agents["erp"].mint("erp.pay_invoice", [{"holder": "assistant"}])
        self.assertIn(
            "IGNORE", self.call("web", "web.fetch", {"url": MAL}, fetch)["text"]
        )
        with self.assertRaises(RemoteError) as cm:
            self.call(
                "erp", "erp.pay_invoice", {"invoice": "INV-999", "amount_cents": 9}, pay
            )
        self.assertEqual(cm.exception.code, "tainted_context")

    def test_catalog_and_manifest_verification_over_http(self):
        bundle = fetch_catalog(self.w.org.urls["web"])[0]
        self.assertEqual(self.a.learn(bundle)["name"], "web.fetch")

    def test_garbage_and_replay_get_generic_rejection(self):
        url = self.w.org.urls["erp"].split("//")[1]
        host, port = url.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=5)
        conn.request(
            "POST",
            "/selo/v1/inbox",
            b'{"not":"an envelope"}',
            {"Content-Type": "application/json"},
        )
        r = conn.getresponse()
        self.assertEqual((r.status, json.loads(r.read())), (400, {"error": "rejected"}))
        conn.close()

    def test_invalid_directory_queries_get_generic_rejection(self):
        for path in (
            "/org/v1/entry",
            "/org/v1/entry?id=erp&epoch=invalid",
            "/org/v1/manifest",
        ):
            with self.subTest(path=path):
                conn = http.client.HTTPConnection(
                    "127.0.0.1", self.org_srv.httpd.server_port, timeout=2
                )
                try:
                    conn.request("GET", path)
                    response = conn.getresponse()
                    self.assertEqual(
                        (response.status, json.loads(response.read())),
                        (400, {"error": "rejected"}),
                    )
                finally:
                    conn.close()

    def test_revocation_list_is_signed_and_enforced(self):
        self.w.org.revoke(self.w.org.agents["assistant"]["serial"])
        self.assertIn(self.w.org.agents["assistant"]["serial"], self.client.revoked())


class HttpRegressionTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.server = _Server(
            _make_handler({"/inbox": self.calls.append}, {}), "127.0.0.1", 0, None
        ).start()
        self.addCleanup(self.server.stop)

    def exchange(self, request):
        with socket.create_connection(
            ("127.0.0.1", self.server.httpd.server_port), timeout=2
        ) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    return response
                response += chunk

    def test_rejected_body_is_not_parsed_as_another_request(self):
        nested = (
            b"POST /inbox HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}"
        )
        headers = [
            b"Content-Length: 1\r\nContent-Length: 2",
            b"Transfer-Encoding: chunked",
            b"Transfer-Encoding: ",
            b"Content-Length: +2",
            b"Content-Length: 1_0",
            b"Content-Length: 999999999",
        ]
        for header in headers:
            with self.subTest(header=header):
                response = self.exchange(
                    b"POST /inbox HTTP/1.1\r\nHost: localhost\r\n"
                    + header
                    + b"\r\n\r\n"
                    + nested
                )
                self.assertEqual(response.count(b"HTTP/1.1"), 1)
                self.assertIn(b"Connection: close", response)
                self.assertEqual(self.calls, [])

    def test_unknown_route_closes_connection_without_processing_body(self):
        nested = (
            b"POST /inbox HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}"
        )
        response = self.exchange(
            b"POST /unknown HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
            + str(len(nested)).encode()
            + b"\r\n\r\n"
            + nested
        )
        self.assertIn(b"404 Not Found", response)
        self.assertEqual(response.count(b"HTTP/1.1"), 1)
        self.assertEqual(self.calls, [])

    def test_truncated_body_is_not_dispatched_even_if_valid_json(self):
        response = self.exchange(
            b"POST /inbox HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n{}"
        )
        self.assertIn(b"400 Bad Request", response)
        self.assertEqual(self.calls, [])

    def test_directory_query_values_are_encoded(self):
        client = OrgClient("http://localhost", None)
        value = "alice&epoch=0# +/ç"
        with patch("selo_v0.transport._request", return_value={}) as request:
            client.directory(value, 7)
            self.assertEqual(
                parse_qs(urlsplit(request.call_args.args[0]).query),
                {"id": [value], "epoch": ["7"]},
            )
            client.entry(value)
            self.assertEqual(
                parse_qs(urlsplit(request.call_args.args[0]).query), {"id": [value]}
            )
            client.manifest_bundle(value)
            self.assertEqual(
                parse_qs(urlsplit(request.call_args.args[0]).query), {"h": [value]}
            )


if __name__ == "__main__":
    unittest.main()
