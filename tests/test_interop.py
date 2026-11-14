"""Ticket #17: interoperabilidade com o a2a-sdk oficial (dependencia so de teste).

* um agente servidor feito com o a2a-sdk, atras de um sidecar SELO, recebe mensagens e
  tarefas de outro agente SELO;
* um cliente do a2a-sdk usa a interface local compativel com A2A do sidecar (modo http);
* o SDK le o Agent Card do SELO sem erro;
* sem a extensao SELO, um cliente A2A comum recebe o erro definido na especificacao.
"""

import asyncio
import json
import time
import unittest
import urllib.request
import uuid

try:
    import httpx
    from a2a.client import ClientConfig, create_client
    from a2a.client.card_resolver import parse_agent_card
    from a2a.types.a2a_pb2 import (
        GetTaskRequest,
        Message,
        Part,
        Role,
        SendMessageRequest,
    )

    HAVE_SDK = True
except ImportError:  # pragma: no cover
    HAVE_SDK = False

from selo import EXTENSION_URI
from tests.e2e import World, rpc, send_message
from tests.harness import Proc


def _card(url):
    with urllib.request.urlopen(url + "/.well-known/agent-card.json", timeout=10) as r:
        return json.loads(r.read())


@unittest.skipUnless(HAVE_SDK, "instale o extra de teste: pip install -e .[interop]")
class InteropTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World().__enter__()
        cls.sdk = Proc(["tests/helpers/sdk_agent.py"])
        cls.b = cls.w.node(
            "b",
            proxied=True,
            start_agent=False,
            cfg={"agent": {"url": cls.sdk.info["url"]}},
        )
        cls.a = cls.w.node("a", cfg={"local": {"mode": "http"}})

    @classmethod
    def tearDownClass(cls):
        cls.w.__exit__(None, None, None)
        cls.sdk.stop()

    def test_selo_peer_talks_to_sdk_server_agent(self):
        resp = self.a.client.call(self.b.url, send_message("ola sdk"))
        self.assertNotIn("error", resp, resp)
        task = resp["result"]["task"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")
        got = self.a.client.call(self.b.url, rpc("GetTask", id=task["id"]))
        self.assertEqual(
            got["result"]["artifacts"][0]["parts"][0]["text"], "sdk eco: ola sdk"
        )
        self.assertFalse(self.b.proxy.plaintext_seen("ola sdk"))

    def test_sdk_reads_selo_card(self):
        card = parse_agent_card(_card(self.b.url))
        self.assertEqual(card.name, "b")
        ext = card.capabilities.extensions[0]
        self.assertEqual(ext.uri, EXTENSION_URI)
        self.assertTrue(ext.required)
        self.assertEqual(card.supported_interfaces[0].protocol_binding, "JSONRPC")
        self.assertEqual(len(card.signatures), 1)

    def test_sdk_client_through_local_a2a_interface(self):
        info = self.a.info["local"]
        with open(info["token_file"]) as fh:
            token = fh.read()
        peer = urllib.parse.quote(self.b.url, safe="")
        base = f"{info['url']}/peers/{peer}"
        headers = {"Authorization": f"Bearer {token}"}

        async def go():
            async with httpx.AsyncClient(headers=headers, timeout=30) as http:
                client = await create_client(
                    base,
                    ClientConfig(streaming=False, httpx_client=http),
                    resolver_http_kwargs={"headers": headers},
                )
                req = SendMessageRequest(
                    message=Message(
                        message_id=str(uuid.uuid4()),
                        role=Role.ROLE_USER,
                        parts=[Part(text="via cliente sdk")],
                    )
                )
                events = [ev async for ev in client.send_message(req)]
                task = events[-1].task
                fetched = await client.get_task(GetTaskRequest(id=task.id))
                return task, fetched

        task, fetched = asyncio.run(go())
        self.assertEqual(fetched.id, task.id)
        self.assertEqual(fetched.artifacts[0].parts[0].text, "sdk eco: via cliente sdk")

    def test_plain_a2a_client_without_extension_gets_defined_error(self):
        async def go():
            async with httpx.AsyncClient(timeout=30) as http:
                client = await create_client(
                    self.b.url, ClientConfig(streaming=False, httpx_client=http)
                )
                req = SendMessageRequest(
                    message=Message(
                        message_id=str(uuid.uuid4()),
                        role=Role.ROLE_USER,
                        parts=[Part(text="em claro")],
                    )
                )
                return [ev async for ev in client.send_message(req)]

        with self.assertRaises(Exception) as cm:
            asyncio.run(go())
        self.assertIn("extension_required", str(cm.exception))
        time.sleep(0.2)
        # nada chegou ao agente
        status = self.a.client.call(self.b.url, send_message("controle"))
        self.assertNotIn("error", status)


if __name__ == "__main__":
    unittest.main()
