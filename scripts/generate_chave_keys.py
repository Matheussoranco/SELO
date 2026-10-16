"""Gera chaves para o protocolo Chave-Organizacao v3.

Estrutura:
- Uma chave de escrow X25519 por organizacao (private: somente a empresa).
- Um par de chaves por agente: Ed25519 (identidade/assinatura) + X25519 (acordo).

Saida (ex: .local/chave):
  org_private.pem    <- protegida; somente a empresa
  org_public.pem     <- distribuida a todos os agentes
  agent-a_identity_*.pem
  agent-a_agreement_*.pem
  agent-b_identity_*.pem
  agent-b_agreement_*.pem
  config.json
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cripto_agent.chave_protocol import AgentKeys, OrgEscrowKeys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=".local/chave")
    parser.add_argument(
        "--org", default="demo-org", help="identificador da organizacao")
    parser.add_argument(
        "--agents", nargs="+", default=["agent-a", "agent-b"])
    args = parser.parse_args()

    out = Path(args.out)
    if out.exists():
        raise FileExistsError(f"pasta ja existe: {out.resolve()}")
    out.mkdir(parents=True)

    org = OrgEscrowKeys.generate(args.org)
    (out / "org_private.pem").write_text(org.private_pem, encoding="utf-8")
    (out / "org_public.pem").write_text(org.public_pem, encoding="utf-8")

    agents = {}
    for name in args.agents:
        keys = AgentKeys.generate(name)
        (out / f"{name}_identity_private.pem").write_text(
            keys.identity_private_pem, encoding="utf-8")
        (out / f"{name}_identity_public.pem").write_text(
            keys.identity_public_pem, encoding="utf-8")
        (out / f"{name}_agreement_private.pem").write_text(
            keys.agreement_private_pem, encoding="utf-8")
        (out / f"{name}_agreement_public.pem").write_text(
            keys.agreement_public_pem, encoding="utf-8")
        agents[name] = {
            "identity_public_pem_path": f"{name}_identity_public.pem",
            "identity_private_pem_path": f"{name}_identity_private.pem",
            "agreement_public_pem_path": f"{name}_agreement_public.pem",
            "agreement_private_pem_path": f"{name}_agreement_private.pem",
        }

    config = {
        "organization": args.org,
        "org_public_pem_path": "org_public.pem",
        "org_private_pem_path": "org_private.pem",
        "agents": agents,
    }
    (out / "config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Chaves geradas em {out.resolve()}")
    print(f"Organizacao: {args.org}  |  Agentes: {', '.join(args.agents)}")
    print("Guarde org_private.pem apenas com a empresa (escrow).")


if __name__ == "__main__":
    main()
