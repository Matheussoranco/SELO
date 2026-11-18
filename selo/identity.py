"""Identidade do agente: chaves, `agent_id` e cadeia de eventos de chave (KEL).

Especificacao, secao 5. A KEL e uma lista de declaracoes `{"body": B, "sigs": [...]}`:
`inception` (seq 0), `rotation` (assinada pela chave anterior e pela nova) e `revocation`
(terminal). O `agent_id` deriva da chave de identidade de genese e nao muda com rotacoes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from . import jcs
from .crypto.primitives import (
    b64u,
    ed25519_from_bytes,
    ed25519_generate,
    ed25519_priv,
    ed25519_pub,
    ed25519_verify,
    sha256,
    unb64u,
    x25519_from_bytes,
    x25519_generate,
    x25519_priv,
    x25519_pub,
)
from .errors import SeloError

ROTATION_GRACE = 300
KEL_DOMAIN = b"selo/1/kel\x00"


def derive_agent_id(genesis_sig_pub: bytes) -> str:
    return "selo:" + b64u(sha256(b"selo/1/agent-id\x00", genesis_sig_pub)[:24])


def statement_hash(body: Dict[str, Any]) -> str:
    return b64u(sha256(jcs.canonicalize(body)))


def _sign(sk: ed25519.Ed25519PrivateKey, body: Dict[str, Any]) -> str:
    return b64u(sk.sign(KEL_DOMAIN + jcs.canonicalize(body)))


@dataclass
class KeyEntry:
    seq: int
    sig_pub: bytes
    agree_pub: bytes
    iat: int


@dataclass
class KelState:
    """Resultado da verificacao de uma KEL."""

    agent_id: str
    entries: List[KeyEntry]
    revoked: bool
    head: str  # hash da ultima declaracao
    revoked_at: Optional[int] = None

    @property
    def seq(self) -> int:
        return self.entries[-1].seq

    @property
    def current(self) -> KeyEntry:
        return self.entries[-1]

    def entry(self, seq: int) -> KeyEntry:
        if not 0 <= seq < len(self.entries):
            raise SeloError("unknown_key_seq", str(seq))
        return self.entries[seq]

    def key_usable(self, seq: int, now: float, msg_iat: Optional[float] = None) -> bool:
        """A chave em `seq` pode ser usada agora? (atual, ou anterior dentro da janela)."""
        if self.revoked:
            return False
        if seq == self.seq:
            return True
        if seq == self.seq - 1:
            t = self.current.iat
            limit = t + ROTATION_GRACE
            return now <= limit and (msg_iat is None or msg_iat <= limit)
        return False


def verify_kel(kel: Any) -> KelState:
    if not isinstance(kel, list) or not kel:
        raise SeloError("bad_kel", "KEL vazia")
    entries: List[KeyEntry] = []
    prev_hash: Optional[str] = None
    agent_id = ""
    revoked, revoked_at = False, None
    last_iat = -1
    for i, st in enumerate(kel):
        if revoked:
            raise SeloError("bad_kel", "declaracao apos revocation")
        if not isinstance(st, dict) or set(st) != {"body", "sigs"}:
            raise SeloError("bad_kel", "forma da declaracao")
        b, sigs = st["body"], st["sigs"]
        if not isinstance(b, dict) or not isinstance(sigs, list) or b.get("seq") != i:
            raise SeloError("bad_kel", "seq")
        iat = b.get("iat")
        if type(iat) is not int or iat < last_iat:
            raise SeloError("bad_kel", "iat")
        last_iat = iat
        t = b.get("t")
        data = KEL_DOMAIN + jcs.canonicalize(b)
        if i == 0:
            if t != "inception" or set(b) != {
                "t",
                "seq",
                "sig_pub",
                "agree_pub",
                "iat",
            }:
                raise SeloError("bad_kel", "inception")
            sig_pub, agree_pub = unb64u(b["sig_pub"]), unb64u(b["agree_pub"])
            if len(sig_pub) != 32 or len(agree_pub) != 32 or len(sigs) != 1:
                raise SeloError("bad_kel", "inception")
            if not ed25519_verify(sig_pub, unb64u(sigs[0]), data):
                raise SeloError("bad_kel", "assinatura da inception")
            agent_id = derive_agent_id(sig_pub)
            entries.append(KeyEntry(0, sig_pub, agree_pub, iat))
        else:
            if b.get("prev") != prev_hash:
                raise SeloError("bad_kel", "prev")
            cur = entries[-1]
            if t == "rotation":
                if (
                    set(b) != {"t", "seq", "prev", "sig_pub", "agree_pub", "iat"}
                    or len(sigs) != 2
                ):
                    raise SeloError("bad_kel", "rotation")
                sig_pub, agree_pub = unb64u(b["sig_pub"]), unb64u(b["agree_pub"])
                if len(sig_pub) != 32 or len(agree_pub) != 32:
                    raise SeloError("bad_kel", "rotation")
                if not (
                    ed25519_verify(cur.sig_pub, unb64u(sigs[0]), data)
                    and ed25519_verify(sig_pub, unb64u(sigs[1]), data)
                ):
                    raise SeloError("bad_kel", "assinatura da rotation")
                entries.append(KeyEntry(i, sig_pub, agree_pub, iat))
            elif t == "revocation":
                if set(b) != {"t", "seq", "prev", "iat"} or len(sigs) != 1:
                    raise SeloError("bad_kel", "revocation")
                if not ed25519_verify(cur.sig_pub, unb64u(sigs[0]), data):
                    raise SeloError("bad_kel", "assinatura da revocation")
                revoked, revoked_at = True, iat
            else:
                raise SeloError("bad_kel", f"tipo {t!r}")
        prev_hash = statement_hash(b)
    return KelState(agent_id, entries, revoked, prev_hash or "", revoked_at)


@dataclass
class Identity:
    """Chaves privadas de um agente (atuais e da geracao anterior) e sua KEL."""

    sig_keys: List[ed25519.Ed25519PrivateKey]
    agree_keys: List[x25519.X25519PrivateKey]
    kel: List[Dict[str, Any]]
    _state: Optional[KelState] = field(default=None, repr=False)

    @classmethod
    def generate(cls, now: int, sig: Any = None, agree: Any = None) -> "Identity":
        """Nova identidade. `sig`/`agree` fixos so para vetores de teste."""
        sig, agree = sig or ed25519_generate(), agree or x25519_generate()
        body = {
            "t": "inception",
            "seq": 0,
            "sig_pub": b64u(ed25519_pub(sig)),
            "agree_pub": b64u(x25519_pub(agree)),
            "iat": int(now),
        }
        return cls([sig], [agree], [{"body": body, "sigs": [_sign(sig, body)]}])

    @property
    def state(self) -> KelState:
        if self._state is None:
            self._state = verify_kel(self.kel)
        return self._state

    @property
    def agent_id(self) -> str:
        return self.state.agent_id

    @property
    def seq(self) -> int:
        return self.state.seq

    @property
    def sig_key(self) -> ed25519.Ed25519PrivateKey:
        return self.sig_keys[-1]

    @property
    def agree_key(self) -> x25519.X25519PrivateKey:
        return self.agree_keys[-1]

    def agree_key_for(self, seq: int, now: float) -> x25519.X25519PrivateKey:
        """Chave de acordo para mensagens enderecadas a `seq` (atual ou anterior na janela)."""
        if not self.state.key_usable(seq, now):
            raise SeloError(
                "wrong_recipient", "seq de chave do destinatario nao aceito"
            )
        offset = self.seq - seq
        if offset >= len(self.agree_keys):
            raise SeloError("wrong_recipient", "chave anterior indisponivel")
        return self.agree_keys[-1 - offset]

    def rotate(self, now: int, sig: Any = None, agree: Any = None) -> None:
        if self.state.revoked:
            raise SeloError("identity_revoked")
        sig, agree = sig or ed25519_generate(), agree or x25519_generate()
        body = {
            "t": "rotation",
            "seq": self.seq + 1,
            "prev": self.state.head,
            "sig_pub": b64u(ed25519_pub(sig)),
            "agree_pub": b64u(x25519_pub(agree)),
            "iat": int(now),
        }
        self.kel.append(
            {"body": body, "sigs": [_sign(self.sig_key, body), _sign(sig, body)]}
        )
        self.sig_keys = [self.sig_key, sig]
        self.agree_keys = [self.agree_key, agree]
        self._state = None

    def revoke(self, now: int) -> None:
        body = {
            "t": "revocation",
            "seq": self.seq + 1,
            "prev": self.state.head,
            "iat": int(now),
        }
        self.kel.append({"body": body, "sigs": [_sign(self.sig_key, body)]})
        self._state = None

    # -- serializacao para o cofre de chaves ----------------------------------------------
    def to_secret(self) -> Dict[str, Any]:
        return {
            "sig": [b64u(ed25519_priv(k)) for k in self.sig_keys],
            "agree": [b64u(x25519_priv(k)) for k in self.agree_keys],
            "kel": self.kel,
        }

    @classmethod
    def from_secret(cls, d: Dict[str, Any]) -> "Identity":
        ident = cls(
            [ed25519_from_bytes(unb64u(k)) for k in d["sig"]],
            [x25519_from_bytes(unb64u(k)) for k in d["agree"]],
            d["kel"],
        )
        st = ident.state
        if (
            ed25519_pub(ident.sig_key) != st.current.sig_pub
            or x25519_pub(ident.agree_key) != st.current.agree_pub
        ):
            raise SeloError("bad_identity", "chaves nao conferem com a KEL")
        return ident


def check_extends(
    pinned: Optional[Tuple[int, str]], state: KelState, kel: List[Dict[str, Any]]
) -> None:
    """Exige que a KEL estenda a fixada (especificacao 5.2). `pinned` = (seq, hash)."""
    if pinned is None:
        return
    seq, head = pinned
    if len(kel) - 1 < seq:
        raise SeloError("kel_rollback", "KEL mais curta que a fixada")
    if statement_hash(kel[seq]["body"]) != head:
        raise SeloError("kel_fork", "KEL diverge da fixada")
