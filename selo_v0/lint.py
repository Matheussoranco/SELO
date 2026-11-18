"""Linter de manifestos e politica: verificacoes estaticas antes da admissao pela organizacao.

Detecta (1) capacidades privilegiadas que aceitam contexto contaminado, (2) fontes nao confiaveis
sem rotulo, (3) descricoes com cara de instrucao ao modelo ou caracteres invisiveis (tool
poisoning), (4) esquemas frouxos e (5) nomes que se confundem (tool shadowing).
As regras 2 e 3 sao heuristicas: reduzem risco, nao o eliminam (a defesa de fundo e o guarda
de contaminacao, que nao depende do texto da descricao).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

SEVERITY = {"error": 2, "warning": 1, "info": 0}

UNTRUSTED_HINTS = re.compile(
    r"\b(web|url|http|html|page|site|browse|fetch|download|scrape|email|e-mail|inbox|message|"
    r"mail|slack|chat|review|comment|document|file|attachment|calendar|rss|feed|search)\b", re.I)
INSTRUCTION_PATTERNS = [
    (re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b", re.I | re.S),
     "asks the model to ignore previous instructions"),
    (re.compile(r"\b(before|after|first|always|must|never)\b.{0,60}\b(send|upload|post|email|read|"
                r"exfiltrate|call|invoke|execute|run)\b", re.I | re.S),
     "imposes a mandatory action on the model"),
    (re.compile(r"\b(do not|don't|never)\b.{0,30}\b(tell|mention|reveal|show|inform)\b.{0,20}\buser\b",
                re.I | re.S), "asks to hide something from the user"),
    (re.compile(r"(~/|/etc/|\.ssh|id_rsa|\.env\b|api[_ -]?key|password|secret|token)", re.I),
     "mentions a sensitive path or secret"),
    (re.compile(r"https?://", re.I), "contains a URL in the description"),
    (re.compile(r"<\s*(important|system|instructions?)\b", re.I), "uses system-prompt-like markup"),
]
PRIVILEGED = {"write", "external"}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    capability: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.upper():7}] {self.rule} {self.capability}: {self.message}"


def _invisible(text: str) -> List[str]:
    bad = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Co", "Cn") or (cat == "Cc" and ch not in "\n\t\r"):
            bad.append(f"U+{ord(ch):04X}")
    return sorted(set(bad))


def _skeleton(name: str) -> str:
    folded = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]", "", folded.replace("l", "1").replace("o", "0").replace("i", "1"))


def lint_manifest(m: Dict[str, Any]) -> List[Finding]:
    name, out = m["name"], []

    def add(rule: str, severity: str, message: str) -> None:
        out.append(Finding(rule, severity, name, message))

    if m["effect"] in PRIVILEGED and not m["forbid_taint"]:
        add("SELO001", "error", f"effect '{m['effect']}' without forbidden labels: would accept a contaminated "
            "context (e.g. WEB, EMAIL)")
    if m["effect"] == "read" and not m["taint_out"] and UNTRUSTED_HINTS.search(
            f"{name} {m['description']}"):
        add("SELO002", "warning", "looks like it reads external content but declares no taint_out")
    hidden = _invisible(m["description"] + name)
    if hidden:
        add("SELO003", "error", f"invisible/control characters in the description: {', '.join(hidden)}")
    for pattern, why in INSTRUCTION_PATTERNS:
        if pattern.search(m["description"]):
            add("SELO004", "warning", f"suspicious description: {why}")
    hits = sum(1 for pattern, _ in INSTRUCTION_PATTERNS if pattern.search(m["description"]))
    if hits >= 3:
        add("SELO008", "error", f"description matches {hits} poisoning heuristics: treat as poisoned")
    if len(m["description"]) > 600:
        add("SELO005", "info", f"long description ({len(m['description'])} chars): review manually")
    props = m["schema"].get("properties")
    if not props:
        add("SELO006", "warning", "schema without 'properties': free-form arguments")
    else:
        for field, rule in props.items():
            if rule.get("type") == "string" and "maxLength" not in rule and "enum" not in rule:
                add("SELO006", "info", f"field '{field}' has no maxLength or enum")
            if "type" not in rule and "enum" not in rule:
                add("SELO006", "warning", f"field '{field}' has no type")
    return out


def lint_manifests(manifests: Iterable[Dict[str, Any]]) -> List[Finding]:
    manifests = list(manifests)
    findings: List[Finding] = []
    for m in manifests:
        findings.extend(lint_manifest(m))
    seen: Dict[str, str] = {}
    for m in manifests:
        key = _skeleton(m["name"])
        if key in seen and seen[key] != m["name"]:
            findings.append(Finding("SELO007", "error", m["name"],
                                    f"name easily confused with '{seen[key]}' (tool shadowing)"))
        seen.setdefault(key, m["name"])
    return sorted(findings, key=lambda f: (-SEVERITY[f.severity], f.capability, f.rule))
