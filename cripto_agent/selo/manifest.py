"""Manifestos de tools/skills assinados, fixados por hash e registrados em um log Merkle.

Defesa contra *tool poisoning* e *rug pull*: o texto que o LLM le (descricao, esquema) so vem
de um manifesto (1) assinado pelo publicador, (2) admitido (contra-assinado) pela organizacao e
(3) incluido no log append-only (arvore de Merkle estilo RFC 6962/9162). Tokens de capacidade
fixam o hash do manifesto; trocar a descricao muda o hash e invalida o token.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from .keys import OrgParams, sign_doc, verify_cert, verify_doc
from .util import SeloError, b64d, b64e, canon, sha256

KINDS = {"tool", "skill"}
EFFECTS = {"read", "write", "external"}
MANIFEST_FIELDS = {"name", "kind", "version", "description", "schema", "publisher",
                   "taint_out", "forbid_taint", "effect", "context"}
CONTEXT_MODES = {"any", "full"}      # "full": o host exige que o cliente cite TODO o contexto


def validate_manifest(m: Any) -> Dict[str, Any]:
    if not isinstance(m, dict) or set(m) != MANIFEST_FIELDS:
        raise SeloError("bad_manifest", "campos")
    if (m["kind"] not in KINDS or m["effect"] not in EFFECTS or m["context"] not in CONTEXT_MODES
            or not isinstance(m["name"], str) or not 0 < len(m["name"]) <= 64
            or not isinstance(m["description"], str) or len(m["description"]) > 2000
            or not isinstance(m["schema"], dict)
            or not all(isinstance(m[k], list) and all(isinstance(t, str) for t in m[k])
                       for k in ("taint_out", "forbid_taint"))):
        raise SeloError("bad_manifest", "valores")
    return m


def new_manifest(name: str, kind: str, description: str, schema: Dict[str, Any], publisher: str,
                 taint_out=(), forbid_taint=(), effect: str = "read", version: str = "1.0.0",
                 context: str = "any") -> Dict[str, Any]:
    if "properties" in schema and "required" not in schema:       # conveniencia: todos obrigatorios
        schema = dict(schema, required=list(schema["properties"]))
    return validate_manifest({
        "name": name, "kind": kind, "version": version, "description": description,
        "schema": schema, "publisher": publisher, "taint_out": sorted(set(taint_out)),
        "forbid_taint": sorted(set(forbid_taint)), "effect": effect, "context": context})


def manifest_hash(m: Dict[str, Any]) -> str:
    return sha256(b"selo/manifest\x00", canon(m)).hex()


# --------------------------------------------------------------------------- argumentos
_MAX_DEPTH = 8


def _resolve(rule: Dict[str, Any], defs: Dict[str, Any]) -> Dict[str, Any]:
    ref = rule.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/") and ref[8:] in defs:
        return defs[ref[8:]]
    return rule


def _check(value: Any, rule: Dict[str, Any], defs: Dict[str, Any], path: str, depth: int) -> None:
    """Subconjunto de JSON Schema: type, enum, anyOf/oneOf, $ref, items, properties/required,
    minimum/maximum, maxLength/maxItems. Palavras-chave desconhecidas sao ignoradas."""
    if depth > _MAX_DEPTH:
        raise ValueError(f"{path}: profundidade excedida")
    rule = _resolve(rule, defs)
    for key in ("anyOf", "oneOf"):
        if key in rule:
            for option in rule[key]:
                try:
                    _check(value, option, defs, path, depth + 1)
                    return
                except ValueError:
                    continue
            raise ValueError(f"{path}: nenhuma alternativa confere")
    if "enum" in rule and value not in rule["enum"]:
        raise ValueError(f"{path}: fora do enum")
    t = rule.get("type")
    if t == "null" and value is not None:
        raise ValueError(f"{path}: esperado null")
    if t == "string" and (not isinstance(value, str) or len(value) > rule.get("maxLength", 100_000)):
        raise ValueError(f"{path}: string invalida")
    if t == "integer" and (type(value) is not int
                           or not rule.get("minimum", -2**63) <= value <= rule.get("maximum", 2**63)):
        raise ValueError(f"{path}: inteiro invalido")
    if t == "number" and (type(value) not in (int, float)
                          or not rule.get("minimum", -1e300) <= value <= rule.get("maximum", 1e300)):
        raise ValueError(f"{path}: numero invalido")
    if t == "boolean" and not isinstance(value, bool):
        raise ValueError(f"{path}: booleano invalido")
    if t == "array":
        if not isinstance(value, list) or len(value) > rule.get("maxItems", 10_000):
            raise ValueError(f"{path}: array invalido")
        for i, item in enumerate(value):
            _check(item, rule.get("items", {}), defs, f"{path}[{i}]", depth + 1)
    if t == "object" or "properties" in rule:
        props = rule.get("properties", {})
        if not isinstance(value, dict):
            raise ValueError(f"{path}: esperado objeto")
        extra = set(value) - set(props)
        if extra and (props or depth == 0) and not rule.get("additionalProperties"):
            raise ValueError(f"{path}: campos extras {sorted(extra)}")
        required = set(rule.get("required", ()))            # padrao JSON Schema: ausente = nenhum
        if required - set(value):
            raise ValueError(f"{path}: campos ausentes {sorted(required - set(value))}")
        for name, sub in props.items():
            if name in value:
                _check(value[name], sub, defs, f"{path}.{name}", depth + 1)


def validate_args(schema: Dict[str, Any], args: Any) -> None:
    """Valida os argumentos de uma chamada contra o esquema do manifesto (levanta ValueError)."""
    if not isinstance(args, dict):
        raise ValueError("argumentos devem ser um objeto")
    _check(args, schema if "type" in schema or "properties" in schema else dict(schema, type="object"),
           schema.get("$defs", {}), "args", 0)


# --------------------------------------------------------------------------- documentos
def publisher_sign(sk: ed25519.Ed25519PrivateKey, cert: Dict[str, Any],
                   manifest: Dict[str, Any]) -> Dict[str, Any]:
    validate_manifest(manifest)
    return {"m": manifest, "pub": sign_doc(sk, "selo/manifest-pub", {"h": manifest_hash(manifest)}),
            "cert": cert}


def org_countersign(org_sk: ed25519.Ed25519PrivateKey, doc: Dict[str, Any]) -> Dict[str, Any]:
    h = manifest_hash(doc["m"])
    out = dict(doc)
    out["org"] = sign_doc(org_sk, "selo/manifest-org", {"h": h, "publisher": doc["m"]["publisher"]})
    return out


def verify_manifest_doc(org: OrgParams, doc: Any, at: float,
                        revoked: Optional[set] = None) -> Dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != {"m", "pub", "cert", "org"}:
        raise SeloError("bad_manifest")
    m = validate_manifest(doc["m"])
    h = manifest_hash(m)
    cert = verify_cert(org, doc["cert"], at=at, revoked=revoked)
    if cert["id"] != m["publisher"] or "publisher" not in cert["roles"]:
        raise SeloError("bad_publisher")
    pub = verify_doc(b64d(cert["sig_pub"]), "selo/manifest-pub", doc["pub"])
    if pub.get("h") != h:
        raise SeloError("bad_manifest", "hash do publicador")
    admitted = verify_doc(org.sig_pub, "selo/manifest-org", doc["org"])
    if admitted != {"h": h, "publisher": m["publisher"]}:
        raise SeloError("bad_manifest", "admissao")
    return m


# --------------------------------------------------------------------------- arvore de Merkle
def _leaf(data: bytes) -> bytes:
    return sha256(b"\x00", data)


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01", left, right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: List[bytes]) -> bytes:
    """MTH(D[n]) do RFC 6962 sobre os dados das folhas."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return _leaf(leaves[0])
    k = _split(n)
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(index: int, leaves: List[bytes]) -> List[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise SeloError("bad_index")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def verify_inclusion(data: bytes, index: int, size: int, path: List[bytes], root: bytes) -> bool:
    """Verificacao iterativa do RFC 9162, secao 2.1.3.2."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = _leaf(data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


class MerkleLog:
    """Log append-only mantido pela organizacao."""

    def __init__(self) -> None:
        self.leaves: List[bytes] = []

    def append(self, doc: Dict[str, Any]) -> int:
        self.leaves.append(canon(doc))
        return len(self.leaves) - 1

    def root(self) -> bytes:
        return merkle_root(self.leaves)

    def proof(self, index: int) -> Dict[str, Any]:
        return {"index": index, "size": len(self.leaves),
                "path": [b64e(p) for p in inclusion_path(index, self.leaves)]}


def make_sth(org_sk: ed25519.Ed25519PrivateKey, log: MerkleLog, ts: int) -> Dict[str, Any]:
    return sign_doc(org_sk, "selo/sth", {"size": len(log.leaves), "root": b64e(log.root()), "ts": ts})


class ManifestStore:
    """Manifestos confiaveis conhecidos por um agente (fixados por hash).

    `resolver(h)` busca (doc, proof, sth) no servico da organizacao quando um hash e desconhecido.
    Hash desconhecido nao e confiavel: o chamador trata a origem como contaminada (fail closed).
    """

    def __init__(self, org: OrgParams, clock: Callable[[], float],
                 resolver: Optional[Callable[[str], Any]] = None,
                 revoked: Optional[set] = None) -> None:
        self.org, self.clock, self.resolver, self.revoked = org, clock, resolver, revoked or set()
        self.by_hash: Dict[str, Dict[str, Any]] = {}
        self.pinned: Dict[str, str] = {}        # nome -> hash aprovado

    def add(self, doc: Any, proof: Dict[str, Any], sth: Any) -> Dict[str, Any]:
        m = verify_manifest_doc(self.org, doc, self.clock(), self.revoked)
        head = verify_doc(self.org.sig_pub, "selo/sth", sth)
        path = [b64d(p) for p in proof["path"]]
        if (proof["size"] != head["size"]
                or not verify_inclusion(canon(doc), proof["index"], head["size"], path,
                                        b64d(head["root"]))):
            raise SeloError("not_in_log")
        self.by_hash[manifest_hash(m)] = m
        return m

    def get(self, h: str) -> Optional[Dict[str, Any]]:
        if h not in self.by_hash and self.resolver is not None:
            try:
                found = self.resolver(h)
                if found is not None:
                    self.add(*found)
            except SeloError:
                return None
        return self.by_hash.get(h)

    def approve(self, h: str) -> Dict[str, Any]:
        """Fixa (pin) o hash aprovado para o nome da capacidade."""
        m = self.get(h)
        if m is None:
            raise SeloError("unknown_manifest")
        self.pinned[m["name"]] = h
        return m

    def check_pin(self, name: str, h: str, approve: Optional[Callable[[str, str], bool]] = None
                  ) -> None:
        """Rejeita (a menos que `approve` aceite) hash diferente do aprovado: defesa de rug pull."""
        pinned = self.pinned.get(name)
        if pinned is None:
            raise SeloError("not_pinned", name)
        if pinned != h:
            if approve is not None and approve(pinned, h):
                self.pinned[name] = h
                return
            raise SeloError("manifest_changed", name)
