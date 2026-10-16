"""Auditoria da organizacao sobre trafego capturado.

Como a organizacao consegue decifrar tudo (por construcao), ela fecha a unica lacuna da
defesa preventiva por contaminacao: a *omissao* de carimbos pelo harness. Duas verificacoes:

1. Completude: toda requisicao de um agente em uma sessao deve citar TODOS os carimbos de
   resultado que lhe foram entregues antes naquela sessao.
2. Propagacao: o carimbo de um resultado deve conter a contaminacao da requisicao
   (apos endossos) uniao as marcas declaradas no manifesto da capacidade.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .org import Organization
from .provenance import effective_taint


def audit_traffic(org: Organization, envelopes: List[Dict[str, Any]], auditor: str,
                  reason: str) -> Dict[str, Any]:
    opened = [org.open(e, auditor, reason) for e in envelopes]
    calls: Dict[str, Any] = {}
    results: List[Any] = []
    order: Dict[str, int] = {}                 # posicao de captura (a lista esta em ordem de captura)
    for position, o in enumerate(opened):
        order[o.header["msg"]] = position
        t = o.body.get("t")
        if t == "call":
            calls[o.header["msg"]] = o
        elif t == "result":
            results.append(o)

    omissions: List[Dict[str, Any]] = []
    for call_id, call in calls.items():
        agent, sid = call.header["sender"], call.body["ctx"]["sid"]
        cited = {s["b"]["h"] for s in call.body["ctx"]["stamps"]}
        for res in results:
            origin = calls.get(res.body["re"])
            if (origin is not None and origin.header["sender"] == agent
                    and origin.body["ctx"]["sid"] == sid and order[res.header["msg"]] < order[call_id]
                    and res.body["stamp"]["b"]["h"] not in cited):
                omissions.append({"agent": agent, "sid": sid, "call": call_id,
                                  "missing_result_from": res.header["sender"],
                                  "cap": res.body["stamp"]["b"]["cap"]})

    propagation: List[Dict[str, Any]] = []
    for res in results:
        origin = calls.get(res.body["re"])
        if origin is None:
            continue
        ctx = origin.body["ctx"]
        need = effective_taint(org.params, ctx["stamps"], ctx["endorsements"], res.header["iat"],
                               lambda h: (org.docs.get(h) or {}).get("m"), org.revoked,
                               sid=ctx["sid"], cap=origin.body["cap"])
        declared = org.docs.get(res.body["stamp"]["b"]["m"])
        if declared is not None:
            need |= set(declared["m"]["taint_out"])
        have = set(res.body["stamp"]["b"]["taint"])
        if not need <= have:
            propagation.append({"host": res.header["sender"], "result": res.header["msg"],
                                "missing_taint": sorted(need - have)})
    return {"messages": len(opened), "omissions": omissions, "propagation": propagation,
            "audit_chain_ok": org.audit.verify()}
