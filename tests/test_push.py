"""Ticket #16: notificacoes push so para endpoints SELO permitidos."""

import time
import unittest

from tests.e2e import World, rpc, send_message


def _wait(fn, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    return fn()


class PushTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World().__enter__()
        cls.c = cls.w.node("c", proxied=True)
        cls.plain = cls.c.agent.info["url"].rstrip("/")  # servidor HTTP que nao e SELO
        cls.a = cls.w.node("a", proxied=True)
        cls.b = cls.w.node("b", cfg={"push": {"allowed_destinations": [cls.plain]}})

    @classmethod
    def tearDownClass(cls):
        cls.w.__exit__(None, None, None)

    def _hook(self):
        return self.a.agent.info["url"] + "_webhook"

    def test_notification_reaches_allowed_destination(self):
        cfg = {"url": self._hook(), "token": "tok-123"}
        resp = self.a.client.call(
            self.b.url,
            send_message("lenta 2", configuration={"taskPushNotificationConfig": cfg}),
        )
        task_id = resp["result"]["task"]["id"]

        def completed():
            return [
                w
                for w in self.a.debug()["webhook"]
                if w["event"].get("statusUpdate", {}).get("taskId") == task_id
                and w["event"]["statusUpdate"]["status"]["state"]
                == "TASK_STATE_COMPLETED"
            ]

        got = _wait(completed)
        self.assertTrue(got, self.a.debug())
        self.assertEqual(got[0]["token"], "tok-123")
        # o agente servidor so falou com a entrada local do proprio sidecar
        sent = [p for p in self.b.debug()["pushes_sent"] if task_id in str(p["event"])]
        self.assertTrue(sent)
        for p in sent:
            self.assertTrue(p["url"].startswith("http://127.0.0.1:"))
            self.assertIn("/push-intake/", p["url"])
        # e a entrega atravessou a rede cifrada
        self.assertTrue(self.a.proxy.find("/selo/v1/push/"))
        self.assertFalse(self.a.proxy.plaintext_seen("TASK_STATE_COMPLETED"))
        self.assertFalse(self.a.proxy.plaintext_seen("tok-123"))

    def test_destination_outside_allowlist_refused_before_connecting(self):
        task = self.a.client.call(self.b.url, send_message("lenta 30"))["result"][
            "task"
        ]
        before = len(self.c.proxy.exchanges)
        third = f"{self.c.url}/selo/v1/push/{'x' * 22}"
        resp = self.a.client.call(
            self.b.url,
            rpc(
                "CreateTaskPushNotificationConfig",
                taskId=task["id"],
                url=third,
                token="t",
            ),
        )
        self.assertEqual(resp["error"]["code"], -32095)
        self.assertEqual(resp["error"]["message"], "push_destination_denied")
        self.assertEqual(len(self.c.proxy.exchanges), before)  # nenhuma conexao a C
        self.a.client.call(self.b.url, rpc("CancelTask", id=task["id"]))

    def test_non_selo_url_refused(self):
        task = self.a.client.call(self.b.url, send_message("lenta 30"))["result"][
            "task"
        ]
        for url in (
            f"{self.plain}/selo/v1/push/{'y' * 22}",  # permitido, mas sem Card SELO
            f"{self.plain}/selo/v1/push/curto",  # ref invalida
            "ftp://exemplo/webhook",
        ):  # nem e HTTP
            with self.subTest(url=url):
                resp = self.a.client.call(
                    self.b.url,
                    rpc(
                        "CreateTaskPushNotificationConfig",
                        taskId=task["id"],
                        url=url,
                        token="t",
                    ),
                )
                self.assertEqual(
                    resp.get("error", {}).get("message"),
                    "push_destination_denied",
                    resp,
                )
        self.a.client.call(self.b.url, rpc("CancelTask", id=task["id"]))

    def test_tampered_or_replayed_notification_rejected(self):
        cfg = {"url": self._hook(), "token": "tok-replay"}
        resp = self.a.client.call(
            self.b.url,
            send_message("rapida", configuration={"taskPushNotificationConfig": cfg}),
        )
        task_id = resp["result"]["task"]["id"]

        def mine():
            return [w for w in self.a.debug()["webhook"] if task_id in str(w["event"])]

        _wait(lambda: len(mine()) >= 2)
        delivered = len(mine())
        ex = [e for e in self.a.proxy.find("/selo/v1/push/") if e.status == 200][-1]
        status, _ = self.a.proxy.replay(ex)
        self.assertEqual(status, 409)
        import copy

        bad = copy.copy(ex)
        body = bytearray(ex.body)
        i = body.index(b'"ct": "') + 10
        body[i] = ord("A") if body[i] != ord("A") else ord("B")
        bad.body = bytes(body)
        status, _ = self.a.proxy.replay(bad)
        self.assertEqual(status, 400)
        time.sleep(0.3)
        self.assertEqual(len(mine()), delivered)


if __name__ == "__main__":
    unittest.main()
