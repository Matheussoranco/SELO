import hashlib
import json
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from cripto_agent.legado.protocol import Agent, Capability, ProtocolError, envelope, make_server, request as wire_request, tls_context
from cripto_agent.legado.__main__ import echo, summarize
from scripts.legado.dev_pki import generate


def request(url, context, message=None):
    return wire_request(url, context, message, expected_fingerprint=NetworkTests.server_fingerprint)


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / 'pki'
        generate(cls.root)
        cfg = json.loads((cls.root / 'agent-b.json').read_text())
        client_cfg = json.loads((cls.root / 'agent-a.json').read_text())
        cls.server_fingerprint = next(iter(client_cfg['peers']))
        cls.agent = Agent('demo-org', 'agent-b', cfg['peers'], [tuple(p) for p in cfg['permissions']], cls.root / 'seen.sqlite3')
        cls.agent.register(Capability('tool', 'echo', 'Echo', echo))
        cls.agent.register(Capability('skill', 'text.stats', 'Stats', summarize))
        cls.context = cls.ctx('agent-a')
        cls.server = make_server(('127.0.0.1', 0), cls.agent, cls.ctx('agent-b', True))
        cls.url = f'https://localhost:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def ctx(cls, name, server=False):
        return tls_context(cls.root / 'ca.crt', cls.root / f'{name}.crt', cls.root / f'{name}.key', server=server)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.agent.db.close()
        cls.tmp.cleanup()

    def msg(self, **changes):
        m = envelope('demo-org', 'agent-a', 'agent-b', 'tool', 'echo', {'text': 'ola'})
        m.update(changes)
        return m

    def rejects(self, message, code):
        with self.assertRaises(ProtocolError) as error:
            request(self.url, self.context, message)
        self.assertEqual(error.exception.code, code)

    def test_catalog_and_execution(self):
        self.assertEqual(len(request(self.url, self.context)['capabilities']), 2)
        self.assertEqual(request(self.url, self.context, self.msg())['result'], {'text': 'ola'})
        result = request(self.url, self.context, self.msg(kind='skill', name='text.stats'))
        self.assertEqual(result['result']['words'], 1)

    def test_replay(self):
        message = self.msg()
        request(self.url, self.context, message)
        self.rejects(message, 'replay')

    def test_replay_persists(self):
        message = self.msg()
        request(self.url, self.context, message)
        other = Agent('demo-org', 'agent-b', {}, [('agent-a', 'tool', 'echo')], self.root / 'seen.sqlite3')
        other.register(Capability('tool', 'echo', '', echo))
        try:
            with self.assertRaises(ProtocolError) as error:
                other.dispatch('agent-a', message)
            self.assertEqual(error.exception.code, 'replay')
        finally:
            other.db.close()

    def test_identity_and_permissions(self):
        for change in [{'sender': 'impostor'}, {'recipient': 'wrong'}, {'organization': 'other'}]:
            self.rejects(self.msg(**change), 'identity_mismatch')
        self.rejects(self.msg(name='shell'), 'forbidden')

    def test_expiration_and_validation(self):
        self.rejects(self.msg(expires_at=time.time() - 1), 'invalid_lifetime')
        self.rejects(self.msg(issued_at=time.time() + 1000), 'invalid_lifetime')
        self.rejects(self.msg(version='2'), 'unsupported_version')
        self.rejects(self.msg(arguments={'command': 'anything'}), 'invalid_arguments')
        self.rejects(self.msg(extra=True), 'invalid_envelope')

    def test_missing_client_certificate(self):
        ctx = ssl.create_default_context(cafile=str(self.root / 'ca.crt'))
        with self.assertRaises((ssl.SSLError, OSError)):
            request(self.url, ctx)

    def test_unregistered_certificate(self):
        with self.assertRaises(ProtocolError) as error:
            request(self.url, self.ctx('agent-b'))
        self.assertEqual(error.exception.code, 'unknown_peer')

    def test_untrusted_server(self):
        with self.assertRaises(ssl.SSLError):
            request(self.url, ssl.create_default_context())

    def test_tls12_rejected(self):
        ctx = self.ctx('agent-a')
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ssl.SSLError):
            request(self.url, ctx)

    def test_http_rejected(self):
        with self.assertRaises(ValueError):
            request('http://localhost', self.context)

    def test_wrong_server_identity(self):
        with self.assertRaisesRegex(ValueError, 'server identity mismatch'):
            wire_request(self.url, self.context, expected_fingerprint='0' * 64)


if __name__ == '__main__':
    unittest.main()
