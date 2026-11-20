"""Capsula de escrow (especificacao, secao 11).

A capsula entrega a organizacao o material que decifra UMA mensagem: no envelope,
`key || base_nonce` do contexto HPKE; na sessao, a chave de mensagem do ratchet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import jcs
from .crypto import hpke
from .crypto.primitives import b64u, sha256, unb64u
from .errors import SeloError

INFO = b"selo/1/escrow"


@dataclass(frozen=True)
class EscrowTarget:
    org: str
    agree_pub: bytes


def make_capsule(target: EscrowTarget, ad: bytes, material: bytes) -> dict[str, Any]:
    enc, ct = hpke.seal_base(target.agree_pub, INFO, sha256(ad), material)
    return {"org": target.org, "enc": b64u(enc), "ct": b64u(ct)}


def capsule_digest(capsule: dict[str, Any] | None) -> bytes:
    return sha256(jcs.canonicalize(capsule) if capsule is not None else b"")


def check_capsule_shape(capsule: Any, org: str) -> None:
    if (
        not isinstance(capsule, dict)
        or set(capsule) != {"org", "enc", "ct"}
        or capsule["org"] != org
    ):
        raise SeloError(
            "escrow_required",
            f"capsula de escrow ausente ou de outra organizacao ({org})",
        )


def open_capsule(capsule: dict[str, Any], escrow_sk, ad: bytes) -> bytes:
    return hpke.open_base(
        unb64u(capsule["enc"]), escrow_sk, INFO, sha256(ad), unb64u(capsule["ct"])
    )
