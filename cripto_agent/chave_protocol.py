"""Protocolo Chave-Organizacao v3 — criptografia de mensagem com escrow da empresa.

Protocolo original de interoperabilidade multiagente, independente de transporte
(mensagem autocontida em JSON). Pode rodar sobre HTTP/HTTPS, filas ou qualquer
canal de rede; a confidencialidade vem da camada da mensagem, não do canal.

Estrutura de chaves original (estilo chaves):

- Cada agente: par Ed25519 (identidade/assinatura) + par X25519 (acordo de chaves).
  A identidade nao depende de maquina nem de perfil do SO; e a chave publica do agente.
- Organizacao: par X25519 de escrow. A chave privada guarda-se somente com a empresa;
  a publica distribuem-se a todos os agentes. A empresa pode descriptografar qualquer
  mensagem para seguranca interna / auditoria.
- Cada mensagem gera um par X25519 efemero do remetente.
- O payload cifra-se com AES-256-GCM sob chave aleatoria K (uma por mensagem).
- K encapsula-se duas vezes via HKDF(X25519): uma para o destinatario, outra para a
  organizacao (escrow). Apenas o destinatario e a empresa recuperam K.
- Assinatura Ed25519 sobre o cabeceario canonico vincula o remetente e ambos os
  encapsulamentos (impedindo troca de wraps).

Fluxo:
  Envio:   gera par efemero -> cifra payload (AES-GCM) -> deriva K_rec e K_org
           via ECDH+H KDF -> encapsula K para destinatario e empresa ->
           assina cabeceario -> envia envelope JSON.
  Rececao: valida assinatura e validade temporal -> tenta unwrap K com sua chave
           X25519 -> se falhar, a empresa pode recuperar K com a chave de escrow ->
           descifra payload -> verifica permissao -> executa tool/skill.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 3
MAX_BODY = 65536
MESSAGE_TTL = 60            # segundos de validade da mensagem apos emissao
CLOCK_SKEW = 120            # tolerancia de diferenca de relogio (segundos)

HKDF_RECIPIENT = b"org-chave/recipient/v3"
HKDF_ESCROW = b"org-chave/escrow/v3"
WRAP_AAD_RECIPIENT = b"org-chave/wrap-recipient/v3"
WRAP_AAD_ESCROW = b"org-chave/wrap-org/v3"

ROUTING_FIELDS = [
    "v", "msg_id", "org", "sender", "recipient",
    "issued", "expires", "sender_x25519_pub", "capability",
]

ENVELOPE_FIELDS = ROUTING_FIELDS + [
    "nonce", "ciphertext", "wrap_recipient", "wrap_org", "signature",
]


class EnvelopeError(Exception):
    """Erro de validacao/descriptografia de envelope."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


# --------------------------------------------------------------------------- helpers
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def hkdf(shared_secret: bytes, context: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=context,
    ).derive(shared_secret)


def _routing_header(envelope: Dict[str, Any]) -> Dict[str, Any]:
    return {k: envelope[k] for k in ROUTING_FIELDS}


# --------------------------------------------------------------------------- key containers
@dataclass(frozen=True)
class AgentKeys:
    """Chaves de um agente: identidade (Ed25519) e acordo (X25519)."""

    agent_id: str
    identity_private_pem: str
    identity_public_pem: str
    agreement_private_pem: str
    agreement_public_pem: str

    @staticmethod
    def generate(agent_id: str) -> "AgentKeys":
        ident_priv = ed25519.Ed25519PrivateKey.generate()
        agree_priv = x25519.X25519PrivateKey.generate()

        def priv_bytes(priv) -> str:
            return priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()

        def pub_bytes(pub) -> str:
            return pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

        return AgentKeys(
            agent_id=agent_id,
            identity_private_pem=priv_bytes(ident_priv),
            identity_public_pem=pub_bytes(ident_priv.public_key()),
            agreement_private_pem=priv_bytes(agree_priv),
            agreement_public_pem=pub_bytes(agree_priv.public_key()),
        )

    @property
    def identity_private_key(self) -> ed25519.Ed25519PrivateKey:
        return serialization.load_pem_private_key(
            self.identity_private_pem.encode(), password=None)

    @property
    def identity_public_key(self) -> ed25519.Ed25519PublicKey:
        return serialization.load_pem_public_key(self.identity_public_pem.encode())

    @property
    def agreement_private_key(self) -> x25519.X25519PrivateKey:
        return serialization.load_pem_private_key(
            self.agreement_private_pem.encode(), password=None)

    @property
    def agreement_public_key(self) -> x25519.X25519PublicKey:
        return serialization.load_pem_public_key(self.agreement_public_pem.encode())


@dataclass(frozen=True)
class OrgEscrowKeys:
    """Chave de escrow organizacional. A privada pertence apenas a empresa."""

    organization: str
    private_pem: str
    public_pem: str

    @staticmethod
    def generate(organization: str) -> "OrgEscrowKeys":
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()

        def priv_bytes(p) -> str:
            return p.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()

        def pub_bytes(p) -> str:
            return p.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

        return OrgEscrowKeys(
            organization=organization,
            private_pem=priv_bytes(priv),
            public_pem=pub_bytes(pub),
        )

    @property
    def private_key(self) -> x25519.X25519PrivateKey:
        return serialization.load_pem_private_key(
            self.private_pem.encode(), password=None)

    @property
    def public_key(self) -> x25519.X25519PublicKey:
        return serialization.load_pem_public_key(self.public_pem.encode())


# --------------------------------------------------------------------------- encryption / decryption
def _unwrap(
    wrapped_b64: str,
    my_priv: x25519.X25519PrivateKey,
    their_pub: x25519.X25519PublicKey,
    hkdf_context: bytes,
    wrap_aad: bytes,
) -> Optional[bytes]:
    """Recupera K de um encapsulamento; retorna None se nao for possivel."""
    wrapped = b64d(wrapped_b64)
    if len(wrapped) < 12 + 16:
        return None
    nonce, ct = wrapped[:12], wrapped[12:]
    shared = my_priv.exchange(their_pub)
    key = hkdf(shared, hkdf_context)
    try:
        return AESGCM(key).decrypt(nonce, ct, wrap_aad)
    except (InvalidTag, ValueError):
        return None


def encrypt_message(
    organization: str,
    sender_id: str,
    recipient_id: str,
    sender_keys: AgentKeys,
    recipient_agreement_pub_pem: str,
    org_agreement_pub_pem: str,
    capability: Dict[str, Any],
    arguments: Dict[str, Any],
    ttl: int = MESSAGE_TTL,
) -> Dict[str, Any]:
    """Cifra e assina uma mensagem para (destinatario) e (empresa/escrow)."""
    payload = {
        "sender": sender_id,
        "recipient": recipient_id,
        "capability": capability,
        "arguments": arguments,
    }
    payload_bytes = json.dumps(payload, allow_nan=False).encode()
    if len(payload_bytes) > MAX_BODY:
        raise ValueError("payload too large")

    msg_id = str(uuid.uuid4())
    now = int(time.time())
    expires = now + ttl

    # Par efemero de acordo deste remetente para esta mensagem.
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    ephemeral_pub_raw = ephemeral_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    header: Dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "msg_id": msg_id,
        "org": organization,
        "sender": sender_id,
        "recipient": recipient_id,
        "issued": now,
        "expires": expires,
        "sender_x25519_pub": b64e(ephemeral_pub_raw),
        "capability": capability,
    }

    # Cifragem do payload com AES-256-GCM, autenticado ao cabeceario de roteamento.
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = canonical(_routing_header(header))
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload_bytes, aad)

    # Encapsulamento duplo de K: uma copia para o destinatario, outra para a empresa.
    recipient_pub = serialization.load_pem_public_key(
        recipient_agreement_pub_pem.encode())
    org_pub = serialization.load_pem_public_key(org_agreement_pub_pem.encode())

    def wrap(target_pub, my_priv, context, aad_label) -> bytes:
        shared = my_priv.exchange(target_pub)
        wrap_key = hkdf(shared, context)
        wrap_nonce = os.urandom(12)
        return wrap_nonce + AESGCM(wrap_key).encrypt(
            wrap_nonce, aes_key, aad_label)

    wrap_recipient = wrap(recipient_pub, ephemeral_priv,
                          HKDF_RECIPIENT, WRAP_AAD_RECIPIENT)
    wrap_org = wrap(org_pub, ephemeral_priv,
                    HKDF_ESCROW, WRAP_AAD_ESCROW)

    header.update({
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "wrap_recipient": b64e(wrap_recipient),
        "wrap_org": b64e(wrap_org),
    })

    # Assinatura vincula todo o cabeceario (incluindo ambos os wraps).
    signature = sender_keys.identity_private_key.sign(canonical(header))
    header["signature"] = b64e(signature)
    return header


def decrypt_message(
    envelope: Dict[str, Any],
    recipient_keys: AgentKeys,
    org_private_pem: Optional[str] = None,
    expected_org: Optional[str] = None,
    sender_identity_public_pem: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Descriptografa uma mensagem como destinatario.

    Retorna (payload, via_org). via_org e False quando o destinatario recuperou
    K com sua propria chave, e True quando so foi possivel via escrow da empresa.
    """
    if not all(k in envelope for k in ENVELOPE_FIELDS):
        raise EnvelopeError("invalid_envelope")
    if envelope["v"] != PROTOCOL_VERSION:
        raise EnvelopeError("unsupported_version")

    now = time.time()
    issued, expires = envelope["issued"], envelope["expires"]
    if (not isinstance(issued, (int, float))
            or not isinstance(expires, (int, float))
            or not now - CLOCK_SKEW <= issued <= now + CLOCK_SKEW
            or not now < expires <= issued + CLOCK_SKEW + MESSAGE_TTL):
        raise EnvelopeError("invalid_lifetime")
    if expected_org and envelope["org"] != expected_org:
        raise EnvelopeError("org_mismatch")

    # Assinatura sobre o cabeceario completo (sem o proprio signature).
    header_for_sig = {k: envelope[k] for k in ENVELOPE_FIELDS if k != "signature"}
    try:
        signature = b64d(envelope["signature"])
    except (ValueError, Exception):
        raise EnvelopeError("invalid_envelope") from None
    if sender_identity_public_pem is None:
        raise EnvelopeError("missing_sender_key")
    sender_pub = serialization.load_pem_public_key(
        sender_identity_public_pem.encode())
    try:
        sender_pub.verify(signature, canonical(header_for_sig))
    except InvalidSignature:
        raise EnvelopeError("bad_signature")

    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
        b64d(envelope["sender_x25519_pub"]))

    # 1) Tentativa com a chave propria do destinatario.
    aes_key = _unwrap(
        envelope["wrap_recipient"], recipient_keys.agreement_private_key,
        ephemeral_pub, HKDF_RECIPIENT, WRAP_AAD_RECIPIENT)
    via_org = False
    if aes_key is None:
        # 2) Recurso ao escrow da empresa (so se a chave privada dela estiver disponivel).
        if org_private_pem is None:
            raise EnvelopeError("cannot_unwrap")
        org_priv = serialization.load_pem_private_key(
            org_private_pem.encode(), password=None)
        aes_key = _unwrap(
            envelope["wrap_org"], org_priv, ephemeral_pub,
            HKDF_ESCROW, WRAP_AAD_ESCROW)
        if aes_key is None:
            raise EnvelopeError("cannot_unwrap")
        via_org = True

    nonce = b64d(envelope["nonce"])
    ciphertext = b64d(envelope["ciphertext"])
    aad = canonical(_routing_header(envelope))
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise EnvelopeError("bad_ciphertext")

    try:
        payload = json.loads(plaintext)
    except ValueError:
        raise EnvelopeError("invalid_payload")
    if not isinstance(payload, dict):
        raise EnvelopeError("invalid_payload")
    if payload.get("sender") != envelope["sender"]:
        raise EnvelopeError("identity_mismatch")
    if payload.get("recipient") != envelope["recipient"]:
        raise EnvelopeError("identity_mismatch")
    if payload.get("capability") != envelope["capability"]:
        raise EnvelopeError("capability_mismatch")
    return payload, via_org


def org_decrypt_message(
    envelope: Dict[str, Any],
    org_private_pem: str,
    sender_identity_public_pem: str,
    expected_org: Optional[str] = None,
) -> Dict[str, Any]:
    """Descriptografa qualquer mensagem usando a chave de escrow da empresa.

    Funcao de seguranca interna: a empresa recupera o conteudo de mensagens
    entre agentes sem precisar da chave privada do destinatario.
    """
    if not all(k in envelope for k in ENVELOPE_FIELDS):
        raise EnvelopeError("invalid_envelope")
    if envelope["v"] != PROTOCOL_VERSION:
        raise EnvelopeError("unsupported_version")

    now = time.time()
    issued, expires = envelope["issued"], envelope["expires"]
    if (not isinstance(issued, (int, float))
            or not isinstance(expires, (int, float))
            or not now - CLOCK_SKEW <= issued <= now + CLOCK_SKEW
            or not now < expires <= issued + CLOCK_SKEW + MESSAGE_TTL):
        raise EnvelopeError("invalid_lifetime")
    if expected_org and envelope["org"] != expected_org:
        raise EnvelopeError("org_mismatch")

    header_for_sig = {k: envelope[k] for k in ENVELOPE_FIELDS if k != "signature"}
    try:
        signature = b64d(envelope["signature"])
    except (ValueError, Exception):
        raise EnvelopeError("invalid_envelope") from None
    sender_pub = serialization.load_pem_public_key(
        sender_identity_public_pem.encode())
    try:
        sender_pub.verify(signature, canonical(header_for_sig))
    except InvalidSignature:
        raise EnvelopeError("bad_signature")

    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
        b64d(envelope["sender_x25519_pub"]))
    org_priv = serialization.load_pem_private_key(
        org_private_pem.encode(), password=None)
    aes_key = _unwrap(
        envelope["wrap_org"], org_priv, ephemeral_pub,
        HKDF_ESCROW, WRAP_AAD_ESCROW)
    if aes_key is None:
        raise EnvelopeError("cannot_unwrap")

    nonce = b64d(envelope["nonce"])
    ciphertext = b64d(envelope["ciphertext"])
    aad = canonical(_routing_header(envelope))
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise EnvelopeError("bad_ciphertext")

    try:
        payload = json.loads(plaintext)
    except ValueError:
        raise EnvelopeError("invalid_payload")
    if not isinstance(payload, dict):
        raise EnvelopeError("invalid_payload")
    return payload


# --------------------------------------------------------------------------- agent + dispatch
@dataclass
class Capability:
    kind: str
    name: str
    description: str
    handler: Any


class SecureAgent:
    """Agente que cifra/descifra, cataloga, autoriza e despacha tools e skills."""

    def __init__(
        self,
        organization: str,
        agent_id: str,
        keys: AgentKeys,
        org_agreement_pub_pem: str,
        org_private_pem: Optional[str],
        identities: Dict[str, str],          # agent_id -> Ed25519 public PEM
        agreement_pubs: Dict[str, str],       # agent_id -> X25519 public PEM
        permissions: Set[Tuple[str, str, str]],
        database: str,
    ):
        self.organization = organization
        self.agent_id = agent_id
        self.keys = keys
        self.org_agreement_pub_pem = org_agreement_pub_pem
        self.org_private_pem = org_private_pem
        self.identities = dict(identities)
        self.agreement_pubs = dict(agreement_pubs)
        self.permissions = set(permissions)
        self.capabilities: Dict[Tuple[str, str], Capability] = {}
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS seen "
            "(sender TEXT, msg_id TEXT, expires REAL, PRIMARY KEY(sender, msg_id))")
        self.db.commit()

    # -- registro / permissoes ------------------------------------------------
    def register(self, capability: Capability) -> None:
        key = (capability.kind, capability.name)
        if capability.kind not in {"tool", "skill"} or key in self.capabilities:
            raise ValueError("invalid or duplicate capability")
        self.capabilities[key] = capability

    def grant(self, sender_id: str, kind: str, name: str) -> None:
        if kind not in {"tool", "skill"}:
            raise ValueError("invalid capability kind")
        self.permissions.add((sender_id, kind, name))

    def revoke(self, sender_id: str, kind: str, name: str) -> None:
        self.permissions.discard((sender_id, kind, name))

    def catalog(self, peer_id: str) -> Dict[str, Any]:
        return {
            "v": str(PROTOCOL_VERSION),
            "organization": self.organization,
            "agent": self.agent_id,
            "capabilities": [
                {"kind": c.kind, "name": c.name, "description": c.description}
                for c in self.capabilities.values()
                if (peer_id, c.kind, c.name) in self.permissions
            ],
        }

    def can_execute(self, sender_id: str, kind: str, name: str) -> bool:
        return (sender_id, kind, name) in self.permissions

    # -- envio ----------------------------------------------------------------
    def encrypt_to(
        self,
        recipient_id: str,
        capability: Dict[str, Any],
        arguments: Dict[str, Any],
        ttl: int = MESSAGE_TTL,
    ) -> Dict[str, Any]:
        if recipient_id not in self.agreement_pubs:
            raise ValueError("unknown recipient agreement key")
        return encrypt_message(
            organization=self.organization,
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            sender_keys=self.keys,
            recipient_agreement_pub_pem=self.agreement_pubs[recipient_id],
            org_agreement_pub_pem=self.org_agreement_pub_pem,
            capability=capability,
            arguments=arguments,
            ttl=ttl,
        )

    # -- recebimento / despacho -----------------------------------------------
    def _check_replay(self, sender_id: str, msg_id: str, expires: float) -> None:
        now = time.time()
        with self.db:
            self.db.execute("DELETE FROM seen WHERE expires < ?", (now,))
            try:
                self.db.execute(
                    "INSERT INTO seen VALUES (?, ?, ?)",
                    (sender_id, msg_id, expires),
                )
            except sqlite3.IntegrityError:
                raise EnvelopeError("replay") from None

    def dispatch(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        sender_id = envelope["sender"]
        if sender_id not in self.identities:
            raise EnvelopeError("unknown_sender")

        payload, via_org = decrypt_message(
            envelope,
            self.keys,
            org_private_pem=self.org_private_pem,
            expected_org=self.organization,
            sender_identity_public_pem=self.identities[sender_id],
        )

        self._check_replay(sender_id, envelope["msg_id"], envelope["expires"])

        kind = payload["capability"]["kind"]
        name = payload["capability"]["name"]
        if not self.can_execute(sender_id, kind, name):
            raise EnvelopeError("forbidden")
        cap_key = (kind, name)
        if cap_key not in self.capabilities:
            raise EnvelopeError("invalid_capability")

        try:
            result = self.capabilities[cap_key].handler(payload.get("arguments", {}))
        except ValueError as error:
            raise EnvelopeError("invalid_arguments") from error

        return {
            "v": str(PROTOCOL_VERSION),
            "msg_id": envelope["msg_id"],
            "sender": self.agent_id,
            "recipient": sender_id,
            "result": result,
            "decrypted_via_org": via_org,
        }

    # -- escrow da empresa -----------------------------------------------------
    def org_decrypt(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Descriptografa qualquer mensagem com a chave de escrow da empresa."""
        if self.org_private_pem is None:
            raise EnvelopeError("org_escrow_unavailable")
        sender_id = envelope["sender"]
        if sender_id not in self.identities:
            raise EnvelopeError("unknown_sender")
        return org_decrypt_message(
            envelope,
            self.org_private_pem,
            self.identities[sender_id],
            expected_org=self.organization,
        )

    def close(self) -> None:
        self.db.close()
