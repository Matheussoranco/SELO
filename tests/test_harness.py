"""O harness funciona: dois processos trocam um byte pelo proxy, e o proxy grava e injeta falhas."""

import unittest

from tests.harness import FakeClock, Proc, TapProxy


class HarnessTest(unittest.TestCase):
    def test_two_processes_exchange_a_byte_through_the_proxy(self):
        server = Proc(["tests/helpers/byte_server.py"])
        proxy = TapProxy(server.info["url"])
        try:
            client = Proc(["tests/helpers/byte_client.py", proxy.url + "/echo"])
            self.assertEqual(client.info["echo"], "2a")
            client.stop()
            self.assertEqual(len(proxy.exchanges), 1)
            self.assertEqual(proxy.exchanges[0].body, b"\x2a")
            status, data = proxy.replay(proxy.exchanges[0])
            self.assertEqual((status, data), (200, b"\x2a"))
        finally:
            proxy.stop()
            server.stop()

    def test_tamper_flips_a_byte(self):
        server = Proc(["tests/helpers/byte_server.py"])
        proxy = TapProxy(server.info["url"])
        try:
            proxy.tamper_next(position=0)
            client = Proc(["tests/helpers/byte_client.py", proxy.url + "/echo"])
            self.assertEqual(client.info["echo"], "2b")
            client.stop()
        finally:
            proxy.stop()
            server.stop()

    def test_fake_clock(self):
        clock = FakeClock(1000)
        clock.advance(5)
        self.assertEqual(clock(), 1005)


if __name__ == "__main__":
    unittest.main()
