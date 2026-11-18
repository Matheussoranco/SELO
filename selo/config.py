"""Configuracao do sidecar (JSON). Valores ausentes recebem os padroes da especificacao."""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

from .errors import SeloError

DEFAULTS: Dict[str, Any] = {
    "name": "agente",
    "state_dir": None,  # obrigatorio
    "public": {"host": "127.0.0.1", "port": 0, "url": None, "tls": None},
    "local": {"mode": "auto", "port": 0},  # auto | pipe | unix | http
    "agent": {"url": None, "inbound_token": None},
    "card": {
        "description": "",
        "skills": None,
        "validity": 24 * 3600,
        "max_card_age": 24 * 3600,
    },
    "keystore": {"backend": "auto"},
    "peers": {},
    "trust": {"allow_unattested": None, "peers": [], "orgs": []},
    "org": None,  # {"descriptor": {...}, "attestation": {...}}
    "push": {"allowed_destinations": []},
    "tls": {"ca_file": None},
    "policy": None,  # "modulo:funcao"
    "clock_offset": 0,  # so para testes (relogio injetavel)
    "capture_path": None,  # grava o trafego bruto recebido/enviado (auditoria)
    "session_ttl": 24 * 3600,
}


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    cfg = from_dict(raw)
    cfg["_path"] = os.path.abspath(path)
    if not os.path.isabs(cfg["state_dir"]):
        cfg["state_dir"] = os.path.join(os.path.dirname(cfg["_path"]), cfg["state_dir"])
    return cfg


def from_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(raw) - set(DEFAULTS) - {"_path"}
    if unknown:
        raise SeloError("bad_config", f"chaves desconhecidas: {sorted(unknown)}")
    cfg = _merge(DEFAULTS, raw)
    if not cfg["state_dir"]:
        raise SeloError("bad_config", "state_dir e obrigatorio")
    return cfg
