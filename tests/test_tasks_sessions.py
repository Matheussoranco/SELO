"""Ticket #12: tarefas A2A sobre sessoes Noise IK + Double Ratchet."""

import json
import os
import time
import unittest

from tests.e2e import World, rpc, send_message


def _wait_state(node, peer_url, task_id, state, timeout=10):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = node.client.call(peer_url, rpc("GetTask", id=task_id))
        if last.get("result", {}).get("status", {}).get("state") == state:
            return last["result"]
        time.sleep(0.1)
    raise AssertionError(f"tarefa nao chegou a {state}: {last}")


class TasksOverSessionsTest(unittest.TestCase):
    def test_lifecycle_get_and_cancel_through_sessions(self):
        with World() as w:
            a, b = w.node("a"), w.node("b", proxied=True)
            first = a.client.call(b.url, send_message("lenta 4"))
            task = first["result"]["task"]
            self.assertEqual(task["status"]["state"], "TASK_STATE_WORKING")
            # a primeira mensagem foi por envelope; depois o sidecar abriu uma sessao
            self.assertEqual(len(b.proxy.find("/selo/v1/envelope")), 1)
            self.assertEqual(
                len([e for e in b.proxy.exchanges if e.path == "/selo/v1/session"]), 1
            )
            done = _wait_state(a, b.url, task["id"], "TASK_STATE_COMPLETED")
            self.assertEqual(done["artifacts"][0]["parts"][-1]["text"], "passo 4/4")
            self.assertTrue(b.proxy.find("/selo/v1/session/"))
            self.assertEqual(
                len(b.proxy.find("/selo/v1/envelope")), 1
            )  # GetTask foi pela sessao

            other = a.client.call(b.url, send_message("lenta 50"))["result"]["task"]
            canceled = a.client.call(b.url, rpc("CancelTask", id=other["id"]))
            self.assertEqual(
                canceled["result"]["status"]["state"], "TASK_STATE_CANCELED"
            )
            self.assertEqual(
                a.client.call(b.url, rpc("GetTask", id=other["id"]))["result"][
                    "status"
                ]["state"],
                "TASK_STATE_CANCELED",
            )
            for needle in ("lenta 50", "passo 4/4", "TASK_STATE_CANCELED"):
                self.assertFalse(b.proxy.plaintext_seen(needle), needle)

    def test_session_and_task_survive_sidecar_restarts(self):
        with World() as w:
            a, b = w.node("a"), w.node("b", proxied=True)
            task = a.client.call(b.url, send_message("lenta 6"))["result"]["task"]
            a.client.call(b.url, rpc("GetTask", id=task["id"]))  # usa a sessao
            sids = {e.path for e in b.proxy.find("/selo/v1/session/")}
            self.assertEqual(len(sids), 1)
            b.restart()  # respondedor reinicia
            r1 = a.client.call(b.url, rpc("GetTask", id=task["id"]))
            self.assertNotIn("error", r1, r1)
            a.restart()  # iniciador reinicia
            done = _wait_state(a, b.url, task["id"], "TASK_STATE_COMPLETED")
            self.assertEqual(done["id"], task["id"])
            # a mesma sessao continuou: nenhum handshake novo, nenhum envelope novo
            self.assertEqual({e.path for e in b.proxy.find("/selo/v1/session/")}, sids)
            self.assertEqual(
                len([e for e in b.proxy.exchanges if e.path == "/selo/v1/session"]), 1
            )
            self.assertEqual(len(b.proxy.find("/selo/v1/envelope")), 1)

    def test_lost_session_falls_back_to_envelope(self):
        with World() as w:
            a, b = w.node("a"), w.node("b", proxied=True)
            task = a.client.call(b.url, send_message("lenta 3"))["result"]["task"]
            a.client.call(b.url, rpc("GetTask", id=task["id"]))
            b.stop_sidecar()
            for suffix in ("", "-wal", "-shm"):
                p = os.path.join(b.state_dir, "state.sqlite3" + suffix)
                if os.path.exists(p):
                    os.remove(p)  # o respondedor perde todas as sessoes
            b.start()
            before = len(b.proxy.find("/selo/v1/envelope"))
            resp = a.client.call(b.url, rpc("GetTask", id=task["id"]))
            self.assertNotIn("error", resp, resp)
            self.assertEqual(resp["result"]["id"], task["id"])
            statuses = [e.status for e in b.proxy.find("/selo/v1/session/")]
            self.assertIn(404, statuses)  # unknown_session
            self.assertEqual(
                len(b.proxy.find("/selo/v1/envelope")), before + 1
            )  # recuo
            self.assertFalse(b.proxy.plaintext_seen(task["id"]))
            # depois do recuo, uma sessao nova e aberta e usada
            self.assertNotIn(
                "error", a.client.call(b.url, rpc("GetTask", id=task["id"]))
            )
            self.assertEqual(
                len([e for e in b.proxy.exchanges if e.path == "/selo/v1/session"]), 2
            )

    def test_replay_and_reordering_rejected(self):
        with World() as w:
            a, b = w.node("a"), w.node("b", proxied=True)
            task = a.client.call(b.url, send_message("lenta 3"))["result"]["task"]
            for _ in range(3):
                a.client.call(b.url, rpc("GetTask", id=task["id"]))
            msgs = b.proxy.find("/selo/v1/session/")
            self.assertGreaterEqual(len(msgs), 3)
            status, body = b.proxy.replay(msgs[-1])  # repeticao da ultima
            self.assertEqual(status, 400)
            status, body = b.proxy.replay(
                msgs[0]
            )  # mensagem antiga entregue depois das novas
            self.assertEqual(status, 400)
            self.assertIn(json.loads(body)["error"], ("bad_ciphertext", "ratchet_skip"))
            # a sessao continua boa para o par legitimo
            self.assertNotIn(
                "error", a.client.call(b.url, rpc("GetTask", id=task["id"]))
            )


if __name__ == "__main__":
    unittest.main()
