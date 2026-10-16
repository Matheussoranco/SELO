"""Compartilhamento de segredo de Shamir (t de n) sobre o corpo primo GF(P), P = 2^256 - 189.

Usado para custodiar a semente mestra da organizacao: nenhuma pessoa isolada a reconstroi.
Um polinomio f de grau t-1 com f(0) = segredo; a parte i e (i, f(i)); t partes
reconstroem f(0) por interpolacao de Lagrange.
"""

from __future__ import annotations

import secrets
from typing import List, Sequence, Tuple

from .util import SeloError

P = 2**256 - 189
Share = Tuple[int, bytes]


def random_secret() -> bytes:
    """Segredo uniforme em [0, P) (rejeicao: a chance de repetir e ~2^-248)."""
    while True:
        value = secrets.randbelow(2**256)
        if value < P:
            return value.to_bytes(32, "big")


def split(secret: bytes, threshold: int, shares: int) -> List[Share]:
    if len(secret) != 32 or int.from_bytes(secret, "big") >= P:
        raise SeloError("bad_secret")
    if not 1 <= threshold <= shares <= 255:
        raise SeloError("bad_threshold")
    coeffs = [int.from_bytes(secret, "big")] + [secrets.randbelow(P) for _ in range(threshold - 1)]
    out: List[Share] = []
    for x in range(1, shares + 1):
        y = 0
        for c in reversed(coeffs):          # Horner
            y = (y * x + c) % P
        out.append((x, y.to_bytes(32, "big")))
    return out


def combine(parts: Sequence[Share]) -> bytes:
    xs = [x for x, _ in parts]
    if len(set(xs)) != len(xs) or not parts:
        raise SeloError("bad_shares")
    total = 0
    for i, (xi, yi) in enumerate(parts):
        num, den = 1, 1
        for j, (xj, _) in enumerate(parts):
            if i != j:
                num = (num * -xj) % P
                den = (den * (xi - xj)) % P
        total = (total + int.from_bytes(yi, "big") * num * pow(den, -1, P)) % P
    return total.to_bytes(32, "big")
