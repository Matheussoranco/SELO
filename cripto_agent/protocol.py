"""HTTPS/mTLS transport and explicit capability dispatch. No remote code loading."""
import hashlib
import http.client
import json
import logging
import sqlite3
import ssl
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

MAX_BODY = 65536
LOG = logging.getLogger(__name__)


class ProtocolError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


@dataclass
class Capability:
    kind: str
    name: str
    description: str
    handler: object


def tls_context(ca, cert, key, *, server=False):
    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    ctx = ssl.create_default_context(purpose, cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


class Agent:
    def __init__(self, organization, agent_id, peers, permissions, database):
        # peers is an administrator-managed mapping of SHA256 certificate -> agent ID.
        self.organization, self.agent_id = organization, agent_id
        self.peers, self.permissions = dict(peers), set(permissions)
        self.capabilities = {}
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS seen (sender TEXT, id TEXT, expires REAL, PRIMARY KEY(sender,id))')
        self.db.commit()

    def register(self, capability):
        key = (capability.kind, capability.name)
        if capability.kind not in {'tool', 'skill'} or key in self.capabilities:
            raise ValueError('invalid or duplicate capability')
        self.capabilities[key] = capability

    def identity(self, certificate):
        peer = self.peers.get(hashlib.sha256(certificate).hexdigest())
        if peer is None:
            raise ProtocolError(403, 'unknown_peer')
        return peer

    def catalog(self, peer):
        return {'version': '1', 'organization': self.organization, 'agent': self.agent_id,
                'capabilities': [{'kind': c.kind, 'name': c.name, 'description': c.description}
                                 for c in self.capabilities.values()
                                 if (peer, c.kind, c.name) in self.permissions]}

    def dispatch(self, peer, message):
        required = {'version', 'id', 'organization', 'sender', 'recipient', 'issued_at', 'expires_at', 'kind', 'name', 'arguments'}
        if not isinstance(message, dict) or set(message) != required:
            raise ProtocolError(400, 'invalid_envelope')
        if any(not isinstance(message[k], str) for k in required - {'issued_at', 'expires_at', 'arguments'}):
            raise ProtocolError(400, 'invalid_types')
        try:
            uuid.UUID(message['id'])
        except ValueError:
            raise ProtocolError(400, 'invalid_id') from None
        if message['version'] != '1':
            raise ProtocolError(400, 'unsupported_version')
        if (message['sender'] != peer or message['organization'] != self.organization
                or message['recipient'] != self.agent_id):
            raise ProtocolError(403, 'identity_mismatch')
        now = time.time()
        issued, expires = message['issued_at'], message['expires_at']
        if (type(issued) not in (int, float) or type(expires) not in (int, float)
                or not now - 120 <= issued <= now + 30 or not now < expires <= issued + 120):
            raise ProtocolError(400, 'invalid_lifetime')
        key = message['kind'], message['name']
        if (peer, *key) not in self.permissions:
            raise ProtocolError(403, 'forbidden')
        if key not in self.capabilities or not isinstance(message['arguments'], dict):
            raise ProtocolError(400, 'invalid_capability')
        with self.db:
            self.db.execute('DELETE FROM seen WHERE expires < ?', (now,))
            try:
                self.db.execute('INSERT INTO seen VALUES (?, ?, ?)', (peer, message['id'], expires))
            except sqlite3.IntegrityError:
                raise ProtocolError(409, 'replay') from None
        # Reserve before execution: failed/uncertain operations must not be blindly retried.
        try:
            result = self.capabilities[key].handler(message['arguments'])
        except ValueError:
            raise ProtocolError(400, 'invalid_arguments') from None
        LOG.info('executed sender=%s id=%s kind=%s name=%s', peer, message['id'], *key)
        return {'version': '1', 'id': message['id'], 'sender': self.agent_id, 'result': result}


def make_server(address, agent, context):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(10)
            super().setup()

        def log_message(self, *_):
            pass  # Do not record payloads or client-controlled request lines.

        def respond(self, status, payload):
            data = json.dumps(payload, allow_nan=False).encode()
            if len(data) > MAX_BODY:
                raise ProtocolError(500, 'result_too_large')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def handle_request(self, post=False):
            try:
                peer = agent.identity(self.connection.getpeercert(binary_form=True))
                if not post and self.path == '/v1/capabilities':
                    return self.respond(200, agent.catalog(peer))
                if not post or self.path != '/v1/messages':
                    raise ProtocolError(404, 'not_found')
                lengths = self.headers.get_all('Content-Length', [])
                if self.headers.get('Transfer-Encoding') or len(lengths) != 1:
                    raise ProtocolError(400, 'invalid_framing')
                if self.headers.get('Content-Type') != 'application/json':
                    raise ProtocolError(415, 'json_required')
                try:
                    size = int(lengths[0])
                except ValueError:
                    raise ProtocolError(400, 'invalid_length') from None
                if not 0 < size <= MAX_BODY:
                    raise ProtocolError(413, 'body_too_large')
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ProtocolError(400, 'truncated_body')
                try:
                    message = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise ProtocolError(400, 'invalid_json') from None
                self.respond(200, agent.dispatch(peer, message))
            except ProtocolError as error:
                self.respond(error.status, {'error': error.code})
            except Exception:
                LOG.error('request_failed')
                self.respond(500, {'error': 'internal_error'})

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request(True)

    class Server(HTTPServer):
        def get_request(self):
            sock, addr = super().get_request()
            sock.settimeout(10)
            try:
                return context.wrap_socket(sock, server_side=True), addr
            except Exception:
                sock.close()
                raise

    return Server(address, Handler)


def envelope(organization, sender, recipient, kind, name, arguments):
    now = time.time()
    return dict(version='1', id=str(uuid.uuid4()), organization=organization, sender=sender,
                recipient=recipient, issued_at=now, expires_at=now + 60,
                kind=kind, name=name, arguments=arguments)


def request(url, context, message=None, *, expected_fingerprint):
    target = urlsplit(url)
    if target.scheme != 'https' or not target.hostname or target.username or target.password or target.query or target.fragment or target.path not in ('', '/'):
        raise ValueError('expected HTTPS origin')
    conn = http.client.HTTPSConnection(target.hostname, target.port or 443, context=context, timeout=10)
    try:
        conn.connect()
        fingerprint = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if fingerprint != expected_fingerprint:
            raise ValueError('server identity mismatch')
        path = '/v1/capabilities' if message is None else '/v1/messages'
        body = None if message is None else json.dumps(message, allow_nan=False).encode()
        if body is not None and len(body) > MAX_BODY:
            raise ValueError('message too large')
        conn.request('GET' if message is None else 'POST', path, body, {'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError('response too large')
        result = json.loads(raw)
        if response.status != 200:
            raise ProtocolError(response.status, result.get('error', 'remote_error'))
        if message is not None and (result.get('id') != message['id'] or result.get('sender') != message['recipient'] or result.get('version') != '1'):
            raise ValueError('response mismatch')
        return result
    finally:
        conn.close()
