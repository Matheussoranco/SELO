"""Protocolo Cripto-Agent v2 - Criptografia de mensagem com escrow organizacional.

Estrutura original com chaves:
- Cada organização possui um par RSA-4096 de escrow. A chave privada fica com a empresa.
- Cada agente possui par RSA-2048 para identidade, assinatura e unwrapping.
- Cada mensagem carrega payload criptografado com AES-256-GCM aleatório.
- A chave simétrica é empacotada duas vezes: para o destinatário e para a empresa.
- Assinatura Ed25519/RSA sobre cabeçalho canônico garante autenticidade.
"""

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

MAX_BODY = 65536

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def canonical(obj: Dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

@dataclass(frozen=True)
class AgentKeys:
    private_pem: str
    public_pem: str

    @staticmethod
    def generate() -> "AgentKeys":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return AgentKeys(priv_pem, pub_pem)

    @property
    def private_key(self):
        return serialization.load_pem_private_key(self.private_pem.encode(), password=None)

    @property
    def public_key(self):
        return serialization.load_pem_public_key(self.public_pem.encode())

@dataclass(frozen=True)
class OrgEscrowKeys:
    private_pem: str
    public_pem: str

    @staticmethod
    def generate() -> "OrgEscrowKeys":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return OrgEscrowKeys(priv_pem, pub_pem)

    @property
    def private_key(self):
        return serialization.load_pem_private_key(self.private_pem.encode(), password=None)

    @property
    def public_key(self):
        return serialization.load_pem_public_key(self.public_pem.encode())

class EnvelopeError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)

def _wrap_key(key: bytes, pub_key) -> bytes:
    return pub_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def _unwrap_key(wrapped: bytes, priv_key) -> bytes:
    return priv_key.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_message(
    organization: str,
    sender_id: str,
    recipient_id: str,
    sender_keys: AgentKeys,
    recipient_pub_pem: str,
    org_pub_pem: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    if len(json.dumps(payload)) > MAX_BODY:
        raise ValueError("payload too large")
    msg_id = str(uuid.uuid4())
    now = int(time.time())
    header = {
        "v": 2,
        "msg_id": msg_id,
        "org": organization,
        "sender": sender_id,
        "recipient": recipient_id,
        "issued": now,
        "expires": now + 60,
        "capability": payload.get("capability", {}),
    }
    # AES-GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    import os
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, json.dumps(payload).encode(), None)

    recipient_pub = serialization.load_pem_public_key(recipient_pub_pem.encode())
    org_pub = serialization.load_pem_public_key(org_pub_pem.encode())

    key_wrap_recipient = _wrap_key(aes_key, recipient_pub)
    key_wrap_org = _wrap_key(aes_key, org_pub)

    # Build envelope without signature for signing
    envelope_no_sig = {
        "v": 2,
        "msg_id": msg_id,
        "org": organization,
        "sender": sender_id,
        "recipient": recipient_id,
        "issued": now,
        "expires": now + 60,
        "capability": payload.get("capability", {}),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "keywrap_recipient": b64e(key_wrap_recipient),
        "keywrap_org": b64e(key_wrap_org),
    }
    # Signature over envelope without signature
    sign_data = canonical(envelope_no_sig)
    signature = sender_keys.private_key.sign(
        sign_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    envelope_no_sig["signature"] = b64e(signature)
    return envelope_no_sig

def decrypt_message(
    envelope: Dict[str, Any],
    recipient_keys: AgentKeys,
    org_private_pem: str | None = None,
    expected_org: str | None = None,
    expected_sender_pub_pem: str | None = None,
) -> Tuple[Dict[str, Any], bool]:
    # validate envelope
    required = ["v","msg_id","org","sender","recipient","issued","expires","capability","nonce","ciphertext","keywrap_recipient","keywrap_org","signature"]
    if not all(k in envelope for k in required):
        raise EnvelopeError("invalid_envelope")
    if envelope["v"] != 2:
        raise EnvelopeError("unsupported_version")
    now = time.time()
    if not (now - 120 <= envelope["issued"] <= now + 30 and now < envelope["expires"] <= envelope["issued"] + 120):
        raise EnvelopeError("invalid_lifetime")
    if expected_org and envelope["org"] != expected_org:
        raise EnvelopeError("org_mismatch")
    # verify signature
    envelope_for_sig = {k: envelope[k] for k in ["v","msg_id","org","sender","recipient","issued","expires","capability","nonce","ciphertext","keywrap_recipient","keywrap_org"]}
    sign_data = canonical(envelope_for_sig)
    signature = b64d(envelope["signature"])
    if expected_sender_pub_pem:
        sender_pub = serialization.load_pem_public_key(expected_sender_pub_pem.encode())
    else:
        # try recipient? No
        raise EnvelopeError("missing_sender_key")
    try:
        sender_pub.verify(
            signature,
            sign_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise EnvelopeError("bad_signature")

    # unwrap key
    wrapped = b64d(envelope["keywrap_recipient"])
    try:
        aes_key = _unwrap_key(wrapped, recipient_keys.private_key)
        decrypted = True
    except Exception:
        if org_private_pem:
            org_priv = serialization.load_pem_private_key(org_private_pem.encode(), password=None)
            aes_key = _unwrap_key(b64d(envelope["keywrap_org"]), org_priv)
            decrypted = False  # decrypted via org escrow
        else:
            raise EnvelopeError("cannot_unwrap")
    nonce = b64d(envelope["nonce"])
    ct = b64d(envelope["ciphertext"])
    aesgcm = AESGCM(aes_key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except InvalidTag:
        raise EnvelopeError("bad_ciphertext")
    payload = json.loads(pt)
    return payload, decrypted

# Compatibility with previous Agent concept
@dataclass
class Capability:
    kind: str
    name: str
    description: str
    handler: Any

class SecureAgent:
    def __init__(self, organization: str, agent_id: str, keys: AgentKeys, org_pub_pem: str, permissions: set):
        self.organization = organization
        self.agent_id = agent_id
        self.keys = keys
        self.org_pub_pem = org_pub_pem
        self.permissions = permissions
        self.capabilities: Dict[Tuple[str,str], Capability] = {}

    def register(self, cap: Capability):
        self.capabilities[(cap.kind, cap.name)] = cap

    def can_execute(self, sender_id: str, kind: str, name: str) -> bool:
        return (sender_id, kind, name) in self.permissions

    def dispatch_secure(self, envelope: Dict[str, Any], sender_pub_pem: str) -> Dict[str, Any]:
        payload, _ = decrypt_message(envelope, self.keys, expected_org=self.organization, expected_sender_pub_pem=sender_pub_pem)
        # basic validation
        if payload.get("sender") != envelope["sender"] or payload.get("recipient") != self.agent_id:
            raise EnvelopeError("identity_mismatch")
        kind = payload["capability"]["kind"]
        name = payload["capability"]["name"]
        if not self.can_execute(envelope["sender"], kind, name):
            raise EnvelopeError("forbidden")
        if (kind, name) not in self.capabilities:
            raise EnvelopeError("invalid_capability")
        result = self.capabilities[(kind, name)].handler(payload.get("arguments", {}))
        return {"version": "2", "msg_id": envelope["msg_id"], "sender": self.agent_id, "result": result}
