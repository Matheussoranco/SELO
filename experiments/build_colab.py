"""Gera o pacote para o Colab: bundle .zip (codigo) + notebook .ipynb.

    python experiments/build_colab.py          ->  colab/selo_bundle.zip, colab/selo_agentdojo.ipynb
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "colab"


def bundle() -> Path:
    OUT.mkdir(exist_ok=True)
    target = OUT / "selo_bundle.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for base in ("cripto_agent", "experiments", "tests"):
            for path in sorted((ROOT / base).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    z.write(path, path.relative_to(ROOT))
        z.write(ROOT / "pyproject.toml", "pyproject.toml")
    return target


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip("\n").splitlines(True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": text.strip("\n").splitlines(True)}


CELLS = [
    md("""
# SELO x AgentDojo — experimentos com LLMs (vLLM)

Roda a matriz de defesas do AgentDojo (sem defesa, spotlighting, repeat-user-prompt) contra o SELO
(`selo_full` e `selo_args`), com modelos Qwen2.5 servidos por vLLM nesta GPU.
**Retomavel**: resultados ja prontos em `results/agentdojo/` sao pulados; se a sessao cair, rode de novo
a partir da celula 3. Ao final, baixe `selo_results.zip` e coloque-o na pasta do projeto.

Ordem: 1) GPU e codigo -> 2) instalar -> 3) configurar -> 4) teste rapido -> 5) rodar tudo -> 6) baixar.
"""),
    md("## 1. GPU e código"),
    code("""
!nvidia-smi --query-gpu=name,memory.total --format=csv
import os, zipfile
from google.colab import files
if not os.path.exists('/content/work/cripto_agent'):
    print('Envie colab/selo_bundle.zip (gerado no seu PC por experiments/build_colab.py)')
    up = files.upload()
    name = next(iter(up))
    os.makedirs('/content/work', exist_ok=True)
    zipfile.ZipFile(name).extractall('/content/work')
%cd /content/work
!ls
"""),
    md("## 2. Instalar (vLLM demora alguns minutos; se pedir, reinicie o runtime e rode de novo a partir daqui)"),
    code("""
!pip -q install agentdojo "cryptography>=46" openai
!pip -q install vllm
"""),
    md("## 3. Configuração"),
    code("""
import subprocess, time, json, os, sys, shutil, requests, itertools
from concurrent.futures import ThreadPoolExecutor
import torch

GPU_GB = torch.cuda.get_device_properties(0).total_memory / 2**30
CC = torch.cuda.get_device_capability(0)[0]
DTYPE = 'bfloat16' if CC >= 8 else 'half'               # T4 nao tem bf16
print(f'GPU {GPU_GB:.0f} GB, compute capability {CC}, dtype {DTYPE}')

# (tag, repositorio HF). 14B: bf16 so cabe com folga em >= 70 GB; senao usa a versao AWQ (4 bits).
MODELS = [('qwen7b', 'Qwen/Qwen2.5-7B-Instruct'),
          ('qwen14b', 'Qwen/Qwen2.5-14B-Instruct' if GPU_GB >= 70 else 'Qwen/Qwen2.5-14B-Instruct-AWQ')]
INJ_SAMPLE = 4          # tarefas de injecao por suite (0 = todas; 4 => ~388 pares por configuracao)
WORKERS = 12            # processos de benchmark em paralelo contra o mesmo servidor vLLM
SUITES = ['workspace', 'travel', 'banking', 'slack']
ATTACK = 'important_instructions'
BENIGN_DEFENSES = ['none', 'selo_full', 'selo_args']
ATTACK_DEFENSES = ['none', 'spotlighting_with_delimiting', 'repeat_user_prompt', 'selo_full', 'selo_args']
PORT = 8000

def start_server(repo):
    stop_server()
    cmd = ['vllm', 'serve', repo, '--port', str(PORT), '--dtype', DTYPE, '--max-model-len', '32768',
           '--enable-auto-tool-choice', '--tool-call-parser', 'hermes', '--enable-prefix-caching',
           '--gpu-memory-utilization', '0.92', '--max-num-seqs', '48']
    if 'AWQ' in repo:
        cmd += ['--quantization', 'awq_marlin' if CC >= 8 else 'awq']
    global SERVER
    SERVER = subprocess.Popen(cmd, stdout=open('vllm.log', 'w'), stderr=subprocess.STDOUT)
    for _ in range(180):
        try:
            if requests.get(f'http://localhost:{PORT}/v1/models', timeout=2).ok:
                print('vLLM pronto:', repo); return
        except Exception:
            pass
        if SERVER.poll() is not None:
            print(open('vllm.log').read()[-3000:]); raise RuntimeError('vLLM caiu')
        time.sleep(10)
    raise RuntimeError('vLLM nao subiu em 30 min; veja vllm.log')

def stop_server():
    global SERVER
    if globals().get('SERVER') is not None and SERVER.poll() is None:
        SERVER.terminate(); SERVER.wait(timeout=60)
    SERVER = None

def job(tag, repo, suite, defense, attack, limit=0, inj=0):
    cmd = [sys.executable, 'experiments/agentdojo_selo.py', 'run', '--port', str(PORT), '--model-id', repo,
           '--tag', tag, '--defense', defense, '--suites', suite]
    if attack: cmd += ['--attack', attack]
    if limit: cmd += ['--limit', str(limit)]
    if inj: cmd += ['--inj-sample', str(inj)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return f'{tag} {suite} {defense} {attack or "benign"}: ' + (r.stdout.strip().splitlines() or ['(sem saida)'])[-1] + \\
           ('' if r.returncode == 0 else f'  ERRO: {r.stderr[-400:]}')
"""),
    md("## 4. Teste rápido (2 tarefas, uma suite) — confira que ASR/utilidade aparecem e nada quebra"),
    code("""
tag, repo = MODELS[0]
start_server(repo)
print(job('smoke', repo, 'banking', 'none', None, limit=2))
print(job('smoke', repo, 'banking', 'selo_full', 'important_instructions', limit=2, inj=2))
print(job('smoke', repo, 'banking', 'selo_args', 'important_instructions', limit=2, inj=2))
"""),
    md("## 5. Rodar tudo (várias horas no total; pode interromper e retomar)"),
    code("""
os.makedirs('results/agentdojo', exist_ok=True)
for tag, repo in MODELS:
    start_server(repo)
    tasks = [(tag, repo, s, d, None) for d in BENIGN_DEFENSES for s in SUITES] + \\
            [(tag, repo, s, d, ATTACK) for d in ATTACK_DEFENSES for s in SUITES]
    with ThreadPoolExecutor(WORKERS) as pool:
        futures = [pool.submit(job, *t, 0, INJ_SAMPLE if t[4] else 0) for t in tasks]
        for f in futures:
            print(f.result(), flush=True)
    stop_server()
"""),
    md("## 6. Empacotar e baixar"),
    code("""
shutil.make_archive('selo_results', 'zip', 'results')
files.download('selo_results.zip')
"""),
]


DEMO_CELLS = [
    md("""
# SELO — demo for reviewers (no GPU, nothing to build)

Runs the narrated demo, the 36-attack matrix, the MCP linter and the micro-benchmark on this VM.
Upload `selo_bundle.zip` when asked (cell 1).
"""),
    code("""
import os, zipfile
from google.colab import files
if not os.path.exists('/content/work/cripto_agent'):
    up = files.upload()
    os.makedirs('/content/work', exist_ok=True)
    zipfile.ZipFile(next(iter(up))).extractall('/content/work')
%cd /content/work
!pip -q install "cryptography>=46"
"""),
    code("!python -m cripto_agent demo"),
    code("!python experiments/protocol_attacks.py --out results/protocol_attacks.json"),
    code("!python -m cripto_agent lint --mcp python tests/fake_mcp_server.py"),
    code("!python -m cripto_agent bench"),
    code("!python -m unittest discover -s tests -p 'test_selo_*.py' 2>&1 | tail -4"),
]

def write_notebook(name: str, cells: list) -> Path:
    nb = {"cells": cells, "metadata": {"colab": {"provenance": []},
                                       "kernelspec": {"name": "python3", "display_name": "Python 3"}},
          "nbformat": 4, "nbformat_minor": 5}
    target = OUT / name
    target.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding="utf-8")
    return target


def notebook() -> Path:
    nb = {"cells": CELLS, "metadata": {"accelerator": "GPU", "colab": {"provenance": []},
                                       "kernelspec": {"name": "python3", "display_name": "Python 3"}},
          "nbformat": 4, "nbformat_minor": 5}
    target = OUT / "selo_agentdojo.ipynb"
    target.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding="utf-8")
    return target


if __name__ == "__main__":
    z, n = bundle(), notebook()
    print(z, z.stat().st_size, "bytes")
    print(n, write_notebook("selo_demo.ipynb", DEMO_CELLS))
