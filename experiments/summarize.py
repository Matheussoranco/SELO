"""Agrega os resultados do AgentDojo (results/agentdojo/*) em tabelas.

    python experiments/summarize.py --root results/agentdojo --out results/agentdojo_summary.json
Saidas: JSON, tabela em texto e trecho LaTeX (results/agentdojo_table.tex).
ASR = fracao de pares (tarefa do usuario, tarefa de injecao) em que o objetivo do atacante foi atingido.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

DEFENSE_ORDER = ["none", "spotlighting_with_delimiting", "repeat_user_prompt", "selo_full", "selo_args"]
LABEL = {"none": "None", "spotlighting_with_delimiting": "Spotlighting",
         "repeat_user_prompt": "Repeat prompt", "selo_full": "\\selo{}-full", "selo_args": "\\selo{}-args"}
MODEL_LABEL = {"qwen7b": "Qwen2.5-7B", "qwen14b": "Qwen2.5-14B"}


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load(root: Path):
    """runs[(model, defense, attack)][suite] = registro"""
    runs = defaultdict(dict)
    for f in sorted(root.glob("*/*.json")):
        rec = json.loads(f.read_text(encoding="utf-8"))
        runs[(rec["model"], rec["defense"], rec["attack"] or "benign")][rec["suite"]] = rec
    return runs


def pct(k, n):
    return f"{100 * k / n:5.1f}" if n else "  n/a"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--root", default="results/agentdojo")
    p.add_argument("--out", default="results/agentdojo_summary.json")
    p.add_argument("--exclude-models", nargs="*", default=["smoke", "mock"])
    args = p.parse_args()
    runs = load(Path(args.root))
    models = sorted({m for m, _, _ in runs if m not in args.exclude_models})
    summary, rows = {}, []
    for model in models:
        for defense in DEFENSE_ORDER:
            benign = runs.get((model, defense, "benign"), {})
            attack = runs.get((model, defense, "important_instructions"), {})
            if not benign and not attack:
                continue
            ub = [v for r in benign.values() for v in r["results"]["utility_results"].values()]
            ua = [v for r in attack.values() for v in r["results"]["utility_results"].values()]
            asr = [v for r in attack.values() for v in r["results"]["security_results"].values()]
            blocked = sum((r["selo_stats"] or {}).get("blocked", 0) for r in attack.values())
            calls = sum((r["selo_stats"] or {}).get("calls", 0) for r in attack.values())
            entry = {
                "benign_utility": [sum(ub), len(ub)], "utility_under_attack": [sum(ua), len(ua)],
                "asr": [sum(asr), len(asr)], "asr_ci": wilson(sum(asr), len(asr)),
                "selo_blocked_calls": blocked, "selo_calls": calls,
                "per_suite_asr": {s: [sum(r["results"]["security_results"].values()),
                                      len(r["results"]["security_results"])] for s, r in attack.items()},
                "per_suite_benign_utility": {s: [sum(r["results"]["utility_results"].values()),
                                                 len(r["results"]["utility_results"])]
                                             for s, r in benign.items()},
            }
            summary[f"{model}/{defense}"] = entry
            lo, hi = entry["asr_ci"]
            rows.append((model, defense, entry, lo, hi))
    Path(args.out).write_text(json.dumps(summary, indent=1), encoding="utf-8")

    print(f"{'modelo':9} {'defesa':30} {'util(benigna)':>14} {'util(ataque)':>13} {'ASR':>7}  IC95% ASR     bloqueios")
    for model, defense, e, lo, hi in rows:
        print(f"{model:9} {defense:30} {pct(*e['benign_utility']):>13}% {pct(*e['utility_under_attack']):>12}% "
              f"{pct(*e['asr']):>6}%  [{100*lo:4.1f},{100*hi:5.1f}]  {e['selo_blocked_calls']}/{e['selo_calls']}")

    tex = ["\\begin{table}[t]", "\\centering\\small",
           "\\caption{AgentDojo with open-weight agents (\\code{important\\_instructions}). Util.: benign "
           "utility; Util.@atk: utility under attack; ASR: attack success rate (lower is better).}"
           "\\label{tab:llm}",
           "\\begin{tabular}{llrrr}", "\\toprule",
           "Model & Defense & Util. (\\%) & Util.@atk (\\%) & ASR (\\%)\\\\", "\\midrule"]
    last = None
    for model, defense, e, lo, hi in rows:
        if last is not None and model != last:
            tex.append("\\midrule")
        name = MODEL_LABEL.get(model, model) if model != last else ""
        last = model
        tex.append(f"{name} & {LABEL[defense]} & {pct(*e['benign_utility']).strip()} & "
                   f"{pct(*e['utility_under_attack']).strip()} & {pct(*e['asr']).strip()} \\\\")
    tex += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    text = "\n".join(tex)
    Path(args.out).with_name("agentdojo_table.tex").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
