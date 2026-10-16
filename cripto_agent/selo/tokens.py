"""Tokens de capacidade atenuaveis (estilo Macaroons, Birgisson et al., NDSS 2014).

  sigma_0 = HMAC(k_host, "selo/tok" || canon({id, cap}))
  sigma_i = HMAC(sigma_{i-1}, canon(c_i))                (cada caveat estreita a autoridade)

Qualquer portador pode ACRESCENTAR caveats (atenuar) mas nao remover: remover exigiria
inverter o HMAC. Somente o servidor da capacidade (dono de k_host) valida o token.
Caveats sao predicados avaliados contra o contexto da requisicao; caveat desconhecido
= falha (fail closed).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Set, Tuple

from hashlib import sha256 as _sha256

from .util import SeloError, b64d, b64e, canon

MAX_CAVEATS = 16


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, _sha256).digest()


@dataclass(frozen=True)
class Token:
    ident: str
    cap: str
    caveats: Tuple[Dict[str, Any], ...]
    sig: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.ident, "cap": self.cap, "cav": list(self.caveats), "sig": b64e(self.sig)}

    @staticmethod
    def from_dict(d: Any) -> "Token":
        if (not isinstance(d, dict) or set(d) != {"id", "cap", "cav", "sig"}
                or not isinstance(d["cav"], list) or len(d["cav"]) > MAX_CAVEATS
                or not isinstance(d["id"], str) or not isinstance(d["cap"], str)
                or not all(isinstance(c, dict) for c in d["cav"])):
            raise SeloError("bad_token")
        return Token(d["id"], d["cap"], tuple(d["cav"]), b64d(d["sig"]))

    def attenuate(self, caveat: Dict[str, Any]) -> "Token":
        """Devolve um token mais restrito; nao precisa da chave do servidor."""
        if len(self.caveats) >= MAX_CAVEATS:
            raise SeloError("too_many_caveats")
        return Token(self.ident, self.cap, self.caveats + (caveat,), _mac(self.sig, canon(caveat)))


def mint(root_key: bytes, cap: str, caveats: Iterable[Dict[str, Any]] = ()) -> Token:
    ident = b64e(os.urandom(12))
    token = Token(ident, cap, (), _mac(root_key, b"selo/tok\x00" + canon({"id": ident, "cap": cap})))
    for caveat in caveats:
        token = token.attenuate(caveat)
    return token


@dataclass
class TokenContext:
    sender: str
    cap: str
    manifest_hash: str
    now: float
    args: Dict[str, Any]
    taint: Set[str]
    uses: Callable[[str], int]             # quantas vezes o token ja foi usado com sucesso


def _field(args: Dict[str, Any], name: Any) -> Any:
    if not isinstance(name, str) or name not in args:
        raise SeloError("caveat_failed", f"argumento ausente: {name}")
    return args[name]


def _check(c: Dict[str, Any], ctx: TokenContext, ident: str) -> None:
    if len(c) != 1:
        raise SeloError("caveat_failed", "caveat malformado")
    (kind, value), = c.items()
    if kind == "holder":
        ok = ctx.sender == value
    elif kind == "exp":
        ok = type(value) is int and ctx.now < value
    elif kind == "manifest":
        ok = ctx.manifest_hash == value
    elif kind == "forbid_taint":
        ok = isinstance(value, list) and not (set(value) & ctx.taint)
    elif kind == "max_uses":
        ok = type(value) is int and ctx.uses(ident) < value
    elif kind == "arg_max":
        if not isinstance(value, dict):
            raise SeloError("caveat_failed", "caveat malformado")
        v = _field(ctx.args, value.get("field"))
        ok = type(v) is int and type(value.get("max")) is int and v <= value["max"]
    elif kind == "arg_in":
        if not isinstance(value, dict):
            raise SeloError("caveat_failed", "caveat malformado")
        v = _field(ctx.args, value.get("field"))
        ok = isinstance(value.get("values"), list) and v in value["values"]
    else:
        raise SeloError("caveat_failed", "caveat desconhecido")
    if not ok:
        raise SeloError("caveat_failed", kind)


def verify(root_key: bytes, token: Token, ctx: TokenContext) -> None:
    sigma = _mac(root_key, b"selo/tok\x00" + canon({"id": token.ident, "cap": token.cap}))
    for caveat in token.caveats:
        sigma = _mac(sigma, canon(caveat))
    if not hmac.compare_digest(sigma, token.sig):
        raise SeloError("bad_token")
    if token.cap != ctx.cap:
        raise SeloError("bad_token", "capacidade diferente")
    for caveat in token.caveats:
        _check(caveat, ctx, token.ident)
