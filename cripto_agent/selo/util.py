"""Utilitarios comuns do protocolo SELO: codificacao canonica, base64url, hash, HKDF e erros."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class SeloError(Exception):
    """Erro de protocolo. `code` e estavel e seguro para registrar; `detail` e opcional."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f"{code}: {detail}")


def check_id(value: Any) -> str:
    if not isinstance(value, str) or not ID_RE.match(value):
        raise SeloError("invalid_id", "identificador deve casar com [a-z0-9][a-z0-9._-]{0,62}")
    return value


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise SeloError("bad_encoding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise SeloError("bad_encoding") from None


def _check_json(obj: Any) -> None:
    """Somente tipos JSON; floats finitos sao aceitos (repr de Python e deterministico)."""
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise SeloError("float_not_allowed", "NaN/Infinity nao sao JSON")
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise SeloError("bad_key_type")
            _check_json(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _check_json(value)
    elif obj is not None and not isinstance(obj, (str, int, bool)):
        raise SeloError("bad_value_type")


def canon(obj: Any) -> bytes:
    """JSON canonico: chaves ordenadas, sem espacos, ASCII. Floats finitos usam o repr de Python
    (ida e volta exata); a interoperabilidade entre linguagens exigiria RFC 8785."""
    _check_json(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def content_hash(obj: Any) -> str:
    """Hash hexadecimal do JSON canonico de um conteudo."""
    return sha256(canon(obj)).hex()


def hkdf(ikm: bytes, info: bytes, salt: bytes | None = None, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def lp(data: bytes) -> bytes:
    """Prefixo de comprimento (2 bytes) para concatenacao sem ambiguidade."""
    return len(data).to_bytes(2, "big") + data
