"""Linha de comando do SELO.

  python -m selo_v0 demo                   cenarios narrados (uso, injecao, rug pull, auditoria)
  python -m selo_v0 bench                  tamanhos e latencias
  python -m selo_v0 lint --mcp CMD...      lista as tools de um servidor MCP (stdio), sugere
                                                rotulos SELO e aponta riscos (poisoning, sumidouros
                                                sem politica, nomes confundiveis)
  python -m selo_v0 lint --json FILE       o mesmo para manifestos em JSON (lista)
"""

import argparse
import json
import sys


def _lint(manifests) -> int:
    from .lint import lint_manifests
    print(f"{'tool':28} {'effect':9} {'taint_out':12} {'forbids':12}")
    for m in manifests:
        print(f"{m['name'][:28]:28} {m['effect']:9} {','.join(m['taint_out']) or '-':12} "
              f"{','.join(m['forbid_taint']) or '-':12}")
    findings = lint_manifests(manifests)
    print()
    for f in findings:
        print(f)
    errors = sum(f.severity == "error" for f in findings)
    print(f"\n{len(manifests)} tools, {errors} errors, "
          f"{sum(f.severity == 'warning' for f in findings)} warnings")
    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="selo_v0", description="Protocolo SELO")
    sub = parser.add_subparsers(dest="cmd", required=True)
    demo_p = sub.add_parser("demo")
    demo_p.add_argument("--lang", choices=["en", "pt"], default="pt")
    sub.add_parser("bench")
    lint = sub.add_parser("lint")
    group = lint.add_mutually_exclusive_group(required=True)
    group.add_argument("--mcp", nargs=argparse.REMAINDER, help="command that starts the MCP server (stdio)")
    group.add_argument("--json", help="JSON file with a list of manifests")
    args = parser.parse_args()
    if args.cmd == "demo":
        from . import demo
        demo.demo(args.lang)
    elif args.cmd == "bench":
        from . import demo
        demo.bench()
    else:
        from .mcp_bridge import McpStdioClient, tool_to_manifest
        if args.mcp:
            client = McpStdioClient(args.mcp).start()
            try:
                manifests = [tool_to_manifest(t, "lint") for t in client.list_tools()]
            finally:
                client.close()
        else:
            with open(args.json, encoding="utf-8") as fh:
                manifests = json.load(fh)
        return _lint(manifests)
    return 0


if __name__ == "__main__":
    sys.exit(main())
