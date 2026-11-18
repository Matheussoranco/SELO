"""SELO como defesa no AgentDojo (https://github.com/ethz-spylab/agentdojo).

Cada chamada de tool do agente vira uma chamada SELO (envelope cifrado e assinado, token de
capacidade, guarda de contaminacao, carimbo de proveniencia) entre o agente `assistant` e o
host `tools`, que executa a funcao original do AgentDojo. Nenhuma tool e modificada.

Politica de rotulos (conservadora, manual, igual para todas as suites):
  - fontes: toda tool de leitura devolve conteudo controlavel por terceiros -> taint_out=[EXTERNAL]
            (excecoes: get_current_day, get_balance);
  - sumidouros: tools que alteram estado ou levam dados para fora -> forbid_taint=[EXTERNAL],
            com os argumentos sensiveis marcados (x-selo-sensitive) para o modo `args`.

Configuracoes (flag --defense):
  none | tool_filter | spotlighting_with_delimiting | repeat_user_prompt   (defesas do AgentDojo)
  selo_full  : cada chamada cita TODO o contexto (garantia do Teorema 2, sem heuristica)
  selo_args  : cada chamada cita so os itens de onde vieram os argumentos sensiveis

Uso:
  python experiments/agentdojo_selo.py groundtruth --mode full|args        (CPU, sem LLM)
  python experiments/agentdojo_selo.py run --port 8000 --defense selo_args  (precisa de vLLM)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from ast import literal_eval
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selo_v0.envelope as _envelope  # noqa: E402
from selo_v0 import RemoteError, Session  # noqa: E402
from selo_v0.manifest import new_manifest  # noqa: E402
from selo_v0.sandbox import World  # noqa: E402

_envelope.MAX_BODY = 16 << 20            # saidas de tools do AgentDojo podem ser grandes
_envelope.MAX_ENVELOPE = 32 << 20

from agentdojo.agent_pipeline import (AgentPipeline, BasePipelineElement, InitQuery,  # noqa: E402
                                      PipelineConfig, ToolsExecutionLoop)
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME  # noqa: E402
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite import get_suites  # noqa: E402
from agentdojo.types import (ChatAssistantMessage, ChatMessage, ChatToolResultMessage,  # noqa: E402
                             text_content_block_from_string)

EXTERNAL = "EXTERNAL"
NEUTRAL_READS = {"get_current_day", "get_balance"}
# sumidouro -> argumentos sensiveis (quem/o que e afetado). None = todos os argumentos.
SINKS: Dict[str, Optional[list]] = {
    # workspace / travel
    "send_email": ["recipients", "cc", "bcc", "attachments"],
    "delete_email": ["email_id"],
    "create_calendar_event": ["participants"],
    "cancel_calendar_event": ["event_id"],
    "reschedule_calendar_event": ["event_id"],
    "add_calendar_event_participants": ["event_id", "participants"],
    "append_to_file": ["file_id"],
    "create_file": ["filename"],
    "delete_file": ["file_id"],
    "share_file": ["file_id", "email", "permission"],
    "reserve_hotel": ["hotel"],
    "reserve_car_rental": ["company"],
    "reserve_restaurant": ["restaurant"],
    # banking
    "send_money": ["recipient", "amount"],
    "schedule_transaction": ["recipient", "amount"],
    "update_scheduled_transaction": ["id", "recipient", "amount"],
    "update_password": ["password"],
    "update_user_info": ["first_name", "last_name", "street", "city"],
    # slack (get_webpage leva a URL para fora: tratado como egresso)
    "add_user_to_channel": ["user", "channel"],
    "send_direct_message": ["recipient"],
    "send_channel_message": ["channel"],
    "invite_user_to_slack": ["user", "user_email"],
    "remove_user_from_slack": ["user"],
    "post_webpage": ["url"],
    "get_webpage": ["url"],
}
SELO_MODES = {"selo_full": "full", "selo_args": "args"}


class SeloStack:
    """Organizacao + host `tools` + cliente `assistant` + usuario, para uma suite do AgentDojo."""

    def __init__(self, suite, mode: str) -> None:
        self.mode = mode
        self.world = World(clock=time.time)
        w = self.world
        w.new_publisher("pub-tools")
        self.host = w.new_agent("tools", token_host=True)
        self.client = w.new_agent("assistant")
        self.user = w.new_principal("user")
        self.current: tuple = (None, None)
        self.tokens: Dict[str, Any] = {}
        self.stats = {"calls": 0, "blocked": 0}
        for tool in suite.tools:
            schema = json.loads(json.dumps(tool.parameters.model_json_schema()))
            schema.setdefault("required", [])            # pydantic omite 'required' quando nao ha
            sink = tool.name in SINKS
            if sink and SINKS[tool.name]:
                for field in SINKS[tool.name]:
                    if field in schema.get("properties", {}):
                        schema["properties"][field]["x-selo-sensitive"] = True
            manifest = new_manifest(
                tool.name, "tool", tool.description[:1900], schema, "pub-tools",
                taint_out=[] if (sink or tool.name in NEUTRAL_READS) else [EXTERNAL],
                forbid_taint=[EXTERNAL] if sink else [],
                effect="external" if sink else "read")
            w.publish(self.host, "pub-tools", manifest, self._handler(tool.name))
            self.tokens[tool.name] = self.host.mint(tool.name, [{"holder": "assistant"}])

    def _handler(self, name: str):
        def handler(args: Dict[str, Any]) -> Dict[str, Any]:
            runtime, env = self.current
            result, error = runtime.run_function(env, name, args)
            return {"out": tool_result_to_str(result), "error": error}
        return handler

    def send(self, entry: Dict[str, Any], envelope: Dict[str, Any]) -> Dict[str, Any]:
        return self.host.handle(envelope)

    def new_session(self, query: str) -> Session:
        session = Session()
        session.observe(self.user.instruct(query), query)
        return session

    def close(self) -> None:
        self.world.close()


class SeloToolsExecutor(BasePipelineElement):
    """Substitui o ToolsExecutor: cada tool call passa pelo protocolo SELO."""

    def __init__(self, stack: SeloStack) -> None:
        self.stack = stack

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        stack = self.stack
        if "selo_session" not in extra_args:
            extra_args = dict(extra_args, selo_session=stack.new_session(query), selo_blocked=set())
        session, blocked_ids = extra_args["selo_session"], extra_args["selo_blocked"]
        stack.current = (runtime, env)
        results = []
        for call in messages[-1]["tool_calls"]:
            def reply(text: str, error: Optional[str] = None) -> None:
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string(text)],
                    tool_call_id=call.id, tool_call=call, error=error))

            if call.function == EMPTY_FUNCTION_NAME:
                reply("", "Empty function name provided. Provide a valid function name.")
                continue
            if call.function not in stack.tokens:
                reply("", f"Invalid tool {call.function} provided.")
                continue
            for k, v in call.args.items():
                if isinstance(v, str) and is_string_list(v):
                    call.args[k] = literal_eval(v)
            stack.stats["calls"] += 1
            try:
                out = stack.client.call("tools", call.function, call.args, stack.tokens[call.function],
                                        session, stack.send, scope=stack.mode)
                reply(out["out"], out["error"])
            except RemoteError as error:
                if error.code in ("invalid_arguments",):
                    reply("", f"Invalid arguments: {error.detail}")
                    continue
                stack.stats["blocked"] += 1
                blocked_ids.add(call.id)
                reply(f"SELO security policy blocked this call ({error.code}): it depends on content "
                      f"from untrusted sources ({error.detail}). Do not retry it; tell the user "
                      "that confirmation is required.", f"SELO:{error.code}")
        return query, runtime, env, [*messages, *results], extra_args


class SeloTraceCleaner(BasePipelineElement):
    """No fim, remove das mensagens as chamadas bloqueadas: o AgentDojo julga alguns ataques pelo
    'rastro' de chamadas tentadas, e uma chamada bloqueada nao aconteceu."""

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        blocked = extra_args.get("selo_blocked") or set()
        if not blocked:
            return query, runtime, env, messages, extra_args
        cleaned = []
        for m in messages:
            if m["role"] == "assistant" and m["tool_calls"]:
                kept = [c for c in m["tool_calls"] if c.id not in blocked]
                m = ChatAssistantMessage(role="assistant", content=m["content"], tool_calls=kept)
            cleaned.append(m)
        return query, runtime, env, cleaned, extra_args


class SeloGroundTruth(BasePipelineElement):
    """Executa o `ground_truth` de uma tarefa atraves do SELO (limite superior de utilidade)."""

    def __init__(self, stack: SeloStack, task, oracle_endorse: bool = False) -> None:
        self.stack, self.task, self.oracle = stack, task, oracle_endorse

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        stack = self.stack
        stack.current = (runtime, env)
        session = stack.new_session(query)
        new_messages = []
        for call in self.task.ground_truth(env):
            new_messages.append(ChatAssistantMessage(role="assistant", tool_calls=[call],
                                                     content=[text_content_block_from_string("")]))
            try:
                try:
                    out = stack.client.call("tools", call.function, call.args, stack.tokens[call.function],
                                            session, stack.send, scope=stack.mode)
                except RemoteError as e:
                    if not (self.oracle and e.code == "tainted_context"):
                        raise
                    # humano ideal: revisa e endossa os itens contaminados citados, depois repete
                    stack.stats["blocked"] += 1
                    for item in [s for s in session.stamps if EXTERNAL in s["b"]["taint"]
                                 or s["b"]["kind"] == "result"]:
                        session.endorse(stack.user.endorse(item, [EXTERNAL], session, cap=call.function))
                        stack.stats["endorsements"] = stack.stats.get("endorsements", 0) + 1
                    out = stack.client.call("tools", call.function, call.args, stack.tokens[call.function],
                                            session, stack.send, scope=stack.mode)
                text, error = out["out"], out["error"]
            except RemoteError as e:
                text, error = "", f"SELO:{e.code}"
                stack.stats["blocked"] += 1
                new_messages.pop()                       # chamada bloqueada nao conta no rastro
            stack.stats["calls"] += 1
            new_messages.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                      tool_call=call, tool_call_id=None, error=error))
        new_messages.append(ChatAssistantMessage(
            role="assistant", content=[text_content_block_from_string(self.task.GROUND_TRUTH_OUTPUT)],
            tool_calls=None))
        return query, runtime, env, [*messages, *new_messages], extra_args


# ---------------------------------------------------------------------------------- execucoes
def ground_truth_utility(mode: Optional[str], suite_names, version: str,
                         oracle: bool = False) -> Dict[str, Any]:
    """Fracao das tarefas do usuario que o proprio gabarito completa sob a politica (sem LLM)."""
    out: Dict[str, Any] = {}
    for name, suite in get_suites(version).items():
        if suite_names and name not in suite_names:
            continue
        done, blocked_tasks, per_task, prompts = 0, 0, {}, 0
        for uid, task in suite.user_tasks.items():
            if mode is None:                                 # referencia: ToolsExecutor original
                from agentdojo.agent_pipeline import GroundTruthPipeline
                pipeline = GroundTruthPipeline(task)
                stack = None
            else:
                stack = SeloStack(suite, mode)
                pipeline = SeloGroundTruth(stack, task, oracle)
            utility, _ = suite.run_task_with_pipeline(pipeline, task, None, {})
            if stack is not None:
                blocked_tasks += stack.stats["blocked"] > 0
                prompts += stack.stats.get("endorsements", 0)
                stack.close()
            per_task[uid] = bool(utility)
            done += bool(utility)
        out[name] = {"user_tasks": len(suite.user_tasks), "utility": done / len(suite.user_tasks),
                     "tasks_with_blocked_calls": blocked_tasks, "endorsements": prompts,
                     "per_task": per_task}
    return out


def build_pipeline(args, suite):
    import openai
    client = openai.OpenAI(api_key="EMPTY", base_url=f"http://localhost:{args.port}/v1")
    model = args.model_id or client.models.list().data[0].id
    llm = OpenAILLM(client, model, temperature=args.temperature)
    llm.name = f"vllm_parsed-{model.split('/')[-1]}"
    stack = None
    if args.defense in SELO_MODES:
        stack = SeloStack(suite, SELO_MODES[args.defense])
        cfg = PipelineConfig(llm=llm, model_id=None, defense=None, system_message_name=None,
                             system_message=None)
        base = AgentPipeline.from_config(cfg)
        system = base.elements[0]
        loop = ToolsExecutionLoop([SeloToolsExecutor(stack), llm])
        pipeline = AgentPipeline([system, InitQuery(), llm, loop, SeloTraceCleaner()])
        pipeline.name = f"{llm.name}-{args.defense}"
    else:
        cfg = PipelineConfig(llm=llm, model_id=None, defense=None if args.defense == "none" else args.defense,
                             system_message_name=None, system_message=None)
        pipeline = AgentPipeline.from_config(cfg)
    return pipeline, stack


def _sample(items: list, k: int) -> list:
    """k itens uniformemente espacados (deterministico)."""
    if k >= len(items):
        return items
    return [items[round(i * (len(items) - 1) / (k - 1))] for i in range(k)] if k > 1 else items[:1]


def _key(k: Any) -> str:
    return "|".join(map(str, k)) if isinstance(k, tuple) else str(k)


def run(args) -> None:
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
    from agentdojo.logging import OutputLogger
    out_dir = Path(args.out) / f"{args.tag}-{args.defense}-{args.attack or 'benign'}"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, suite in get_suites(args.version).items():
        if args.suites and name not in args.suites:
            continue
        result_file = out_dir / f"{name}.json"
        if result_file.exists() and not args.force:
            print("ja existe:", result_file)
            continue
        pipeline, stack = build_pipeline(args, suite)
        user_tasks = list(suite.user_tasks)[: args.limit] if args.limit else None
        inj_tasks = _sample(list(suite.injection_tasks), args.inj_sample) if args.inj_sample else None
        started = time.time()
        with OutputLogger(str(out_dir / "logs"), live=None):
            if args.attack:
                attacker = load_attack(args.attack, suite, pipeline)
                res = benchmark_suite_with_injections(
                    pipeline, suite, attacker, out_dir / "logs", force_rerun=args.force,
                    user_tasks=user_tasks, injection_tasks=inj_tasks, benchmark_version=args.version)
            else:
                res = benchmark_suite_without_injections(
                    pipeline, suite, out_dir / "logs", force_rerun=args.force, user_tasks=user_tasks,
                    benchmark_version=args.version)
        dump = {section: {_key(k): v for k, v in res[section].items()} for section in res}
        record = {"suite": name, "defense": args.defense, "attack": args.attack, "model": args.tag,
                  "seconds": round(time.time() - started, 1), "results": dump,
                  "selo_stats": stack.stats if stack else None}
        result_file.write_text(json.dumps(record, indent=1), encoding="utf-8")
        ut = list(res["utility_results"].values())
        sec = list(res["security_results"].values())
        print(f"{name}: utilidade={sum(ut)/max(len(ut),1):.3f} "
              f"ASR={(sum(sec)/len(sec) if sec else float('nan')):.3f} n={len(ut)} "
              f"({record['seconds']}s) stats={record['selo_stats']}")
        if stack:
            stack.close()


def main() -> None:
    warnings.filterwarnings("ignore")
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("groundtruth")
    g.add_argument("--mode", choices=["none", "full", "args"], required=True)
    g.add_argument("--suites", nargs="*", default=[])
    g.add_argument("--oracle-endorse", action="store_true",
                   help="humano ideal endossa os itens contaminados quando ha bloqueio")
    g.add_argument("--version", default="v1.2.2")
    g.add_argument("--out", default="results/groundtruth.json")
    r = sub.add_parser("run")
    r.add_argument("--port", type=int, default=8000)
    r.add_argument("--model-id", default=None)
    r.add_argument("--tag", default="model")
    r.add_argument("--defense", default="none",
                   choices=["none", "tool_filter", "spotlighting_with_delimiting", "repeat_user_prompt",
                            "selo_full", "selo_args"])
    r.add_argument("--attack", default=None, help="ex.: important_instructions (omitido = sem ataque)")
    r.add_argument("--suites", nargs="*", default=[])
    r.add_argument("--version", default="v1.2.2")
    r.add_argument("--temperature", type=float, default=0.0)
    r.add_argument("--limit", type=int, default=0, help="N primeiras tarefas do usuario")
    r.add_argument("--inj-sample", type=int, default=0,
                   help="K tarefas de injecao por suite, uniformemente espacadas (0 = todas)")
    r.add_argument("--out", default="results/agentdojo")
    r.add_argument("--force", action="store_true")
    args = p.parse_args()
    if args.cmd == "groundtruth":
        res = ground_truth_utility(None if args.mode == "none" else args.mode, args.suites,
                                   args.version, args.oracle_endorse)
        label = args.mode + ("+endorse" if args.oracle_endorse else "")
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        existing = json.loads(Path(args.out).read_text()) if Path(args.out).exists() else {}
        existing[label] = res
        Path(args.out).write_text(json.dumps(existing, indent=1), encoding="utf-8")
        for s, v in res.items():
            print(f"{label:13} {s:10} tarefas={v['user_tasks']:3} utilidade={v['utility']:.3f} "
                  f"com_bloqueio={v['tasks_with_blocked_calls']:3} endossos={v['endorsements']}")
    else:
        run(args)


if __name__ == "__main__":
    main()
