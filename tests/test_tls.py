"""Ticket #9: transporte HTTP entre hosts com TLS obrigatorio fora do loopback."""

import os
import subprocess
import sys
import tempfile
import unittest

from selo.errors import SeloError
from selo.net import HttpClient, check_url
from tests.e2e import World, free_port, send_message
from tests.harness import TcpTap
from tests.tlsutil import lan_ip, make_ca, make_server_cert


class TlsRuleTest(unittest.TestCase):
    def test_client_refuses_plain_http_outside_loopback(self):
        for url in (
            "http://10.0.0.5:8443",
            "http://example.com",
            "http://192.168.1.10",
        ):
            with self.subTest(url=url), self.assertRaises(SeloError) as cm:
                check_url(url)
            self.assertEqual(cm.exception.code, "tls_required")
        for url in (
            "http://127.0.0.1:1",
            "http://localhost:2",
            "http://[::1]:3",
            "https://example.com",
        ):
            check_url(url)

    def test_sidecar_refuses_to_start_without_tls_outside_loopback(self):
        tmp = tempfile.mkdtemp(prefix="selo-notls-")
        cfg = os.path.join(tmp, "c.json")
        with open(cfg, "w") as fh:
            fh.write(
                '{"name": "n", "state_dir": "st", "public": {"host": "0.0.0.0", "port": 0},'
                ' "agent": {"url": "http://127.0.0.1:9/"}, "keystore": {"backend": "file"}}'
            )
        env = dict(os.environ, SELO_KEY_PASSWORD="x")
        r = subprocess.run(
            [sys.executable, "-m", "selo", "sidecar", "--config", cfg],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("tls_required", r.stderr)
        self.assertIn("0.0.0.0", r.stderr)


class TlsEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="selo-tls-")
        cls.ca, cert, key = make_ca(cls.dir)
        cls.cert, cls.key = make_server_cert(
            cls.dir, "bob", cert, key, ["localhost", "127.0.0.1"]
        )
        _, other_cert, other_key = make_ca(cls.dir, "Outra CA")
        cls.bad_cert, cls.bad_key = make_server_cert(
            cls.dir, "impostor", other_cert, other_key, ["localhost", "127.0.0.1"]
        )

    def test_message_over_tls_and_tap_sees_no_header(self):
        with World() as w:
            port = free_port()
            tap = TcpTap("127.0.0.1", port)
            try:
                b = w.node(
                    "bob",
                    cfg={
                        "public": {
                            "port": port,
                            "url": f"https://localhost:{tap.port}",
                            "tls": {"cert": self.cert, "key": self.key},
                        }
                    },
                )
                a = w.node("alice", cfg={"tls": {"ca_file": self.ca}})
                self.assertTrue(b.url.startswith("https://"))
                secret = "conteudo-sob-tls-91c2"
                resp = a.client.call(b.url, send_message(secret))
                self.assertNotIn("error", resp, resp)
                self.assertEqual(b.received()[-1]["text"], secret)
                self.assertGreater(len(tap.data), 1000)
                for needle in (
                    secret.encode(),
                    a.agent_id.encode(),
                    b.agent_id.encode(),
                    b"selo/1",
                    b"/selo/v1/envelope",
                    b'"recipient"',
                ):
                    self.assertFalse(tap.seen(needle), needle)
            finally:
                tap.stop()

    def test_untrusted_certificate_fails(self):
        with World() as w:
            b = w.node(
                "bob",
                cfg={"public": {"tls": {"cert": self.bad_cert, "key": self.bad_key}}},
            )
            a = w.node("alice", cfg={"tls": {"ca_file": self.ca}})
            resp = a.client.call(b.url, send_message("nao deve chegar"))
            self.assertEqual(resp["error"]["message"], "tls_error")
            self.assertEqual(b.received(), [])

    def test_client_without_ca_rejects_private_ca(self):
        with self.assertRaises(SeloError) as cm:
            with World() as w:
                b = w.node(
                    "bob", cfg={"public": {"tls": {"cert": self.cert, "key": self.key}}}
                )
                HttpClient().request("GET", b.url + "/.well-known/agent-card.json")
        self.assertEqual(cm.exception.code, "tls_error")


@unittest.skipUnless(
    os.environ.get("SELO_TEST_LAN") == "1" and lan_ip(),
    "defina SELO_TEST_LAN=1 para ouvir no IP de rede (pode abrir o firewall)",
)
class LanInterfaceTest(unittest.TestCase):
    def test_non_loopback_interface_with_tls(self):
        ip = lan_ip()
        d = tempfile.mkdtemp(prefix="selo-lan-")
        ca, cert, key = make_ca(d)
        c, k = make_server_cert(d, "lan", cert, key, [ip])
        with World() as w:
            b = w.node(
                "bob", cfg={"public": {"host": ip, "tls": {"cert": c, "key": k}}}
            )
            a = w.node("alice", cfg={"tls": {"ca_file": ca}})
            self.assertTrue(b.url.startswith(f"https://{ip}:"))
            self.assertNotIn(
                "error", a.client.call(b.url, send_message("pela interface de rede"))
            )
            plain = b.url.replace("https://", "http://")
            self.assertEqual(
                a.client.call(plain, send_message("x"))["error"]["message"],
                "tls_required",
            )


if __name__ == "__main__":
    unittest.main()
