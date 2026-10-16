"""Gera chaves para protocolo v2 com escrow organizacional."""
import argparse
import json
from pathlib import Path
from cripto_agent.secure_protocol import AgentKeys, OrgEscrowKeys

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=".local/secure")
    args = p.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)

    org = OrgEscrowKeys.generate()
    (out / "org_private.pem").write_text(org.private_pem)
    (out / "org_public.pem").write_text(org.public_pem)

    agents = {}
    for name in ["agent-a", "agent-b"]:
        k = AgentKeys.generate()
        (out / f"{name}_private.pem").write_text(k.private_pem)
        (out / f"{name}_public.pem").write_text(k.public_pem)
        agents[name] = {
            "public_pem_path": f"{name}_public.pem",
            "private_pem_path": f"{name}_private.pem",
        }

    config = {
        "organization": "demo-org",
        "org_public_pem_path": "org_public.pem",
        "org_private_pem_path": "org_private.pem",
        "agents": agents,
    }
    (out / "config.json").write_text(json.dumps(config, indent=2))
    print(f"Chaves geradas em {out.resolve()}")

if __name__ == "__main__":
    main()
