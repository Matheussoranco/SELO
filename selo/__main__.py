"""Linha de comando do SELO.

  selo init     --config C --name N --agent-url U [--host H] [--port P] [--local-mode M] [--keystore B]
  selo sidecar  --config C                     sobe o sidecar (anuncia READY {json})
  selo rotate   --config C                     gira as chaves (sidecar parado)
  selo revoke   --config C                     revoga a identidade (terminal; sidecar parado)
  selo send     --config C --peer R --text T   envia SendMessage pelo canal local
  selo whoami   --config C
  selo org ...                                 organizacao: ver `selo org --help`
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid


def _cmd_init(a: argparse.Namespace) -> int:
    if os.path.exists(a.config) and not a.force:
        print(f"{a.config} ja existe (use --force)", file=sys.stderr)
        return 1
    cfg = {"name": a.name, "state_dir": a.state_dir or f"{a.name}-state",
           "public": {"host": a.host, "port": a.port},
           "local": {"mode": a.local_mode}, "agent": {"url": a.agent_url},
           "keystore": {"backend": a.keystore}}
    if a.url:
        cfg["public"]["url"] = a.url
    if a.tls_cert:
        cfg["public"]["tls"] = {"cert": a.tls_cert, "key": a.tls_key}
    os.makedirs(os.path.dirname(os.path.abspath(a.config)), exist_ok=True)
    with open(a.config, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    print(f"configuracao escrita em {a.config}")
    return 0


def _sidecar_offline(path: str):
    from .config import load
    from .sidecar import Sidecar
    return Sidecar(load(path))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="selo", description="SELO: A2A cifrado de ponta a ponta")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init")
    p.add_argument("--config", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--agent-url", required=True)
    p.add_argument("--state-dir")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--url", help="URL publica anunciada no Card")
    p.add_argument("--tls-cert")
    p.add_argument("--tls-key")
    p.add_argument("--local-mode", default="auto", choices=["auto", "pipe", "unix", "http"])
    p.add_argument("--keystore", default="auto", choices=["auto", "dpapi", "keychain", "secret-service", "file"])
    p.add_argument("--force", action="store_true")

    for name in ("sidecar", "rotate", "revoke", "whoami"):
        q = sub.add_parser(name)
        q.add_argument("--config", required=True)

    q = sub.add_parser("send")
    q.add_argument("--config", required=True)
    q.add_argument("--peer", required=True)
    q.add_argument("--text", required=True)

    from .org import add_cli as add_org_cli
    add_org_cli(sub)

    a = ap.parse_args(argv)
    from .errors import SeloError
    try:
        if a.cmd == "init":
            return _cmd_init(a)
        if a.cmd == "sidecar":
            from .config import load
            from .sidecar import run_forever
            run_forever(load(a.config))
            return 0
        if a.cmd in ("rotate", "revoke"):
            sc = _sidecar_offline(a.config)
            try:
                sc.rotate_keys() if a.cmd == "rotate" else sc.revoke_identity()
                print(json.dumps({"agent_id": sc.identity.agent_id, "kel_len": len(sc.identity.kel)}))
            finally:
                sc.store.close()
            return 0
        if a.cmd in ("send", "whoami"):
            from .config import load
            from .local import LocalClient
            client = LocalClient(load(a.config)["state_dir"])
            if a.cmd == "whoami":
                print(json.dumps(client.whoami(), indent=2))
                return 0
            rpc = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                   "params": {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                                          "parts": [{"text": a.text}]}}}
            print(json.dumps(client.call(a.peer, rpc), indent=2, ensure_ascii=False))
            return 0
        if a.cmd == "org":
            from .org import run_cli
            return run_cli(a)
    except SeloError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
