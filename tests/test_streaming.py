"""Ticket #15: streaming SSE protegido pela sessao com ratchet."""

import threading
import time
import unittest

from tests.e2e import World, rpc, send_message


def _stream(node, peer, msg):
    return list(node.client.stream(peer, msg))


def _texts(events):
    out = []
    for ev in events:
        art = ev.get("result", {}).get("artifactUpdate")
        if art:
            out.append(art["artifact"]["parts"][0]["text"])
    return out


def _flip(event: bytes) -> bytes:
    i = event.index(b'"ct": "') + 12
    b = bytearray(event)
    b[i] = ord("A") if b[i] != ord("A") else ord("B")
    return bytes(b)


class StreamingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World().__enter__()
        cls.a = cls.w.node("a")
        cls.b = cls.w.node("b", proxied=True)

    @classmethod
    def tearDownClass(cls):
        cls.w.__exit__(None, None, None)

    def test_events_arrive_in_order(self):
        events = _stream(
            self.a, self.b.url, send_message("lenta 3", method="SendStreamingMessage")
        )
        self.assertNotIn("error", events[-1], events[-1])
        self.assertIn("task", events[0]["result"])
        self.assertEqual(_texts(events), ["passo 1/3", "passo 2/3", "passo 3/3"])
        self.assertEqual(
            events[-1]["result"]["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED",
        )
        self.assertTrue(
            any(
                "text/event-stream" in e.resp_headers.get("Content-Type", "")
                for e in self.b.proxy.find("/selo/v1/session/")
            )
        )
        for needle in ("passo 2/3", "artifactUpdate", "TASK_STATE_COMPLETED"):
            self.assertFalse(self.b.proxy.plaintext_seen(needle), needle)

    def _faulty(self, mutator, text="lenta 2"):
        self.a.client.call(self.b.url, send_message("garante sessao"))
        self.b.proxy.mutate_next_stream(mutator)
        return _stream(
            self.a, self.b.url, send_message(text, method="SendStreamingMessage")
        )

    def test_tampered_event_rejected(self):
        events = self._faulty(lambda i, e: [_flip(e)] if i == 1 else [e])
        self.assertIn("task", events[0]["result"])
        self.assertEqual(events[-1]["error"]["message"], "bad_ciphertext")
        self.assertEqual(len(events), 2)

    def test_repeated_event_rejected(self):
        events = self._faulty(lambda i, e: [e, e] if i == 1 else [e])
        self.assertEqual(events[-1]["error"]["message"], "bad_ciphertext")
        self.assertEqual(len(events), 3)  # task, evento 1, erro

    def test_reordered_events_rejected(self):
        held = []

        def swap(i, e):
            if i == 1:
                held.append(e)
                return []
            if i == 2:
                return [e] + held
            return [e]

        events = self._faulty(swap)
        self.assertEqual(events[-1]["error"]["message"], "stream_out_of_order")

    def test_truncated_stream_detected(self):
        task = self.a.client.call(self.b.url, send_message("rapida"))["result"]["task"]
        self.b.proxy.mutate_next_stream(
            lambda i, e: [] if i == 1 else [e]
        )  # some o marcador end
        events = _stream(self.a, self.b.url, rpc("SubscribeToTask", id=task["id"]))
        self.assertEqual(events[-1]["error"]["message"], "stream_truncated")

    def test_cancel_ends_the_stream(self):
        got, done = [], threading.Event()

        def consume():
            for ev in self.a.client.stream(
                self.b.url, send_message("lenta 100", method="SendStreamingMessage")
            ):
                got.append(ev)
            done.set()

        threading.Thread(target=consume, daemon=True).start()
        deadline = time.time() + 10
        while len(got) < 2 and time.time() < deadline:
            time.sleep(0.05)
        task_id = got[0]["result"]["task"]["id"]
        canceled = self.a.client.call(self.b.url, rpc("CancelTask", id=task_id))
        self.assertEqual(canceled["result"]["status"]["state"], "TASK_STATE_CANCELED")
        self.assertTrue(done.wait(10), "o stream nao terminou depois do cancelamento")
        self.assertEqual(
            got[-1]["result"]["statusUpdate"]["status"]["state"], "TASK_STATE_CANCELED"
        )
        self.assertLess(len(_texts(got)), 100)

    def test_subscribe_to_running_task(self):
        task = self.a.client.call(self.b.url, send_message("lenta 3"))["result"]["task"]
        events = _stream(self.a, self.b.url, rpc("SubscribeToTask", id=task["id"]))
        self.assertEqual(events[0]["result"]["task"]["id"], task["id"])
        self.assertEqual(
            events[-1]["result"]["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED",
        )


class StreamingHttpLocalModeTest(unittest.TestCase):
    def test_sse_through_local_http_interface(self):
        with World() as w:
            a = w.node("a", cfg={"local": {"mode": "http"}})
            b = w.node("b")
            events = _stream(
                a, b.url, send_message("lenta 2", method="SendStreamingMessage")
            )
            self.assertEqual(_texts(events), ["passo 1/2", "passo 2/2"])


if __name__ == "__main__":
    unittest.main()
