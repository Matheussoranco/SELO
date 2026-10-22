"""E1 -- custo do protocolo: tamanhos, latencia de seal/open/chamada e sobrecarga por tool call no AgentDojo.

    python experiments/overhead.py --out results/overhead.json [--agentdojo]
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

from cripto_agent.selo import Session  # noqa: E402
from cripto_agent.selo.envelope import open_envelope, seal  # noqa: E402
from cripto_agent.selo.sandbox import World  # noqa: E402
from cripto_agent.selo.util import b64d  # noqa: E402


def median_ms(fn, n: int) -> float:
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(xs), 4)


def micro(n: int = 1000) -> dict:
    w = World().standard()
    a, erp = w.agents["assistant"], w.agents["erp"]
    alice = w.principals["alice"]
    entry = a.remote_entry("erp")
    pub = b64d(entry["agree_pub"])
    out = {"seal_open": {}, "call_vs_stamps": {}, "sizes": {}}
    for size in (256, 4096, 65536):
        body = {"t": "ping", "payload": "x" * size}
        env = seal(org=w.org.params, sender_id="assistant", sender_sk=a.sig_sk, sender_cert=a.cert,
                   recipient_id="erp", recipient_epoch=entry["epoch"], recipient_agree_pub=pub,
                   body=body, now=a.now())
        out["seal_open"][str(size)] = {
            "seal_ms": median_ms(lambda: seal(org=w.org.params, sender_id="assistant", sender_sk=a.sig_sk,
                                              sender_cert=a.cert, recipient_id="erp",
                                              recipient_epoch=entry["epoch"], recipient_agree_pub=pub,
                                              body=body, now=a.now()), n),
            "open_ms": median_ms(lambda: open_envelope(env, org=w.org.params,
                                                       agree_sk=erp.keys.agree_key(entry["epoch"]),
                                                       my_id="erp", now=a.now()), n),
            "envelope_bytes": len(json.dumps(env, separators=(",", ":")))}
    tok = erp.mint("erp.get_balance", [{"holder": "assistant"}])
    for k in (0, 1, 8, 32, 128):
        s = Session()
        for _ in range(k):
            s.observe(alice.instruct("x"), "x")
        base = list(s.stamps)

        def call():
            s.stamps = list(base)
            a.call("erp", "erp.get_balance", {"account": "matriz"}, tok, s, w.send)
        out["call_vs_stamps"][str(k)] = median_ms(call, 150)
    w.traffic.clear()
    a.call("erp", "erp.get_balance", {"account": "matriz"}, tok, Session(), w.send)
    out["sizes"] = {"request_bytes": len(json.dumps(w.traffic[0], separators=(",", ":"))),
                    "response_bytes": len(json.dumps(w.traffic[1], separators=(",", ":"))),
                    "certificate_bytes": len(json.dumps(a.cert, separators=(",", ":"))),
                    "token_bytes": len(json.dumps(tok.to_dict(), separators=(",", ":")))}
    w.close()
    return out


def agentdojo_overhead(version: str = "v1.2.2") -> dict:
    warnings.filterwarnings("ignore")
    import agentdojo_selo as A
    from agentdojo.agent_pipeline import GroundTruthPipeline
    from agentdojo.task_suite import get_suites
    res = {}
    for name, suite in get_suites(version).items():
        t_direct = t_selo = 0.0
        calls = 0
        for task in suite.user_tasks.values():
            t = time.perf_counter()
            suite.run_task_with_pipeline(GroundTruthPipeline(task), task, None, {})
            t_direct += time.perf_counter() - t
            stack = A.SeloStack(suite, "args")
            t = time.perf_counter()
            suite.run_task_with_pipeline(A.SeloGroundTruth(stack, task, oracle_endorse=True), task, None, {})
            t_selo += time.perf_counter() - t
            calls += stack.stats["calls"]
            stack.close()
        res[name] = {"tool_calls": calls, "overhead_ms_per_call": round(1000 * (t_selo - t_direct) / calls, 3)}
    return res


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="results/overhead.json")
    p.add_argument("--n", type=int, default=1000)
    p.add_argument("--agentdojo", action="store_true")
    args = p.parse_args()
    result = {"machine": {"python": platform.python_version(), "platform": platform.platform(),
                          "processor": platform.processor()}, "micro": micro(args.n)}
    if args.agentdojo:
        result["agentdojo"] = agentdojo_overhead()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps(result, indent=1))
