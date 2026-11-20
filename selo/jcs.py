"""JSON Canonicalization Scheme (RFC 8785).

`canonicalize(obj)` devolve os bytes UTF-8 canonicos de um valor JSON do Python (dict, list,
str, int, float, bool, None). Regras da RFC:

* objetos com chaves ordenadas pelas unidades UTF-16 do nome;
* strings com o escape minimo de JSON (so `"`, `\` e controles < 0x20), o resto literal;
* numeros serializados como o `Number.prototype.toString` do ECMAScript sobre um double IEEE 754.
"""

from __future__ import annotations

import functools
import math
from typing import Any

from .errors import SeloError

MAX_SAFE_INT = 2**53 - 1

_ESC = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}
def canonicalize(value: Any) -> bytes:
    out: list = []
    _write(value, out)
    return "".join(out).encode("utf-8")


# Dispatch table for type handlers (replaces long if/elif chain)
@functools.singledispatch
def _write(v: Any, out: list) -> None:
    raise SeloError("bad_json", f"tipo nao serializavel: {type(v).__name__}")


@_write.register(type(None))
def _(v: None, out: list) -> None:
    out.append("null")


@_write.register(bool)
def _(v: bool, out: list) -> None:
    out.append("true" if v else "false")


@_write.register(str)
def _(v: str, out: list) -> None:
    out.append(_string(v))


@_write.register(int)
def _(v: int, out: list) -> None:
    if abs(v) > MAX_SAFE_INT:
        raise SeloError("bad_json", "inteiro fora de +-(2^53-1)")
    out.append(str(v))


@_write.register(float)
def _(v: float, out: list) -> None:
    out.append(number(v))


@_write.register(dict)
def _(v: dict, out: list) -> None:
    items = []
    for k in v:
        if not isinstance(k, str):
            raise SeloError("bad_json", "chave de objeto nao e string")
        items.append(k)
    items.sort(key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    out.append("{")
    for i, k in enumerate(items):
        if i:
            out.append(",")
        out.append(_string(k))
        out.append(":")
        _write(v[k], out)
    out.append("}")


@_write.register(list)
@_write.register(tuple)
def _(v: list | tuple, out: list) -> None:
    out.append("[")
    for i, item in enumerate(v):
        if i:
            out.append(",")
        _write(item, out)
    out.append("]")


def _string(s: str) -> str:
    parts = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            raise SeloError("bad_json", "surrogate isolado em string")
        if c in _ESC:
            parts.append(_ESC[c])
        elif c < 0x20:
            parts.append("\\u{:04x}".format(c))
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def number(x: float) -> str:
    """Number.prototype.toString do ECMAScript (ECMA-262, 7.1.12.1) para um double."""
    if math.isnan(x) or math.isinf(x):
        raise SeloError("bad_json", "NaN e infinito nao sao JSON")
    if x == 0:
        return "0"  # inclui -0
    sign = "-" if x < 0 else ""
    # repr do Python produz o menor numero de digitos que reproduz o double, como o ES.
    r = repr(abs(x))
    if "e" in r:
        mant, exp = r.split("e")
        e10 = int(exp)
    else:
        mant, e10 = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    # posicao do ponto decimal relativa ao inicio de `digits`: valor = 0.d1d2... * 10^n
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) - lead_zeros + e10
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = (
            digits[0]
            + ("." + digits[1:] if k > 1 else "")
            + "e"
            + ("+" if e > 0 else "-")
            + str(abs(e))
        )
    return sign + s
