"""Demo executavel do protocolo Chave-Organizacao v3.

Fluxo:
  1. Gera chaves (org escrow + agente A e B).
  2. B registra tool/echo e skill/text.stats e concede permissao a A.
  3. A cifra e envia uma mensagem para B; B descifra, autoriza e executa.
  4. A empresa (chave privada de escrow) descriptografa a mesma mensagem
     sem a chave privada de B — seguranca interna.
  5. Reenvio da mesma mensagem e rejeitado (replay).

Roda diretamente em memoria; nao depende de rede nem de TLS.
"""

import json
import sys
from pathlib import Path

# Permite rodar direto: python examples/chave_demo.py
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cripto_agent.chave_protocol import (  # noqa: E402
    AgentKeys, OrgEscrowKeys, Capability, SecureAgent, EnvelopeError,
    encrypt_message, decrypt_message, org_decrypt_message,
)


def echo(arguments):
    if set(arguments) != {"text"} or not isinstance(arguments["text"], str):
        raise ValueError("esperado {'text': str}")
    return {"text": arguments["text"]}


def stats(arguments):
    text = arguments["text"]
    return {"words": len(text.split()), "chars": len(text)}


def load_or_generate(base: Path):
    base.mkdir(parents=True, exist_ok=True)
    cfg_path = base / "config.json"
    if cfg_path.exists():
        return json.loads(cfg_path.read_text(encoding="utf-8"))

    org = OrgEscrowKeys.generate("demo-org")
    (base / "org_private.pem").write_text(org.private_pem, encoding="utf-8")
    (base / "org_public.pem").write_text(org.public_pem, encoding="utf-8")

    agents = {}
    for name in ("agent-a", "agent-b"):
        keys = AgentKeys.generate(name)
        (base / f"{name}_identity_private.pem").write_text(
            keys.identity_private_pem, encoding="utf-8")
        (base / f"{name}_identity_public.pem").write_text(
            keys.identity_public_pem, encoding="utf-8")
        (base / f"{name}_agreement_private.pem").write_text(
            keys.agreement_private_pem, encoding="utf-8")
        (base / f"{name}_agreement_public.pem").write_text(
            keys.agreement_public_pem, encoding="utf-8")
        agents[name] = {
            "identity_public_pem_path": f"{name}_identity_public.pem",
            "identity_private_pem_path": f"{name}_identity_private.pem",
            "agreement_public_pem_path": f"{name}_agreement_public.pem",
            "agreement_private_pem_path": f"{name}_agreement_private.pem",
        }

    config = {
        "organization": "demo-org",
        "org_public_pem_path": "org_public.pem",
        "org_private_pem_path": "org_private.pem",
        "agents": agents,
    }
    cfg_path.write_text(json.dumps(config, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    return config


def read(base, rel):
    return (base / rel).read_text(encoding="utf-8")


def main() -> None:
    base = Path(".local/chave_demo")
    cfg = load_or_generate(base)
    org = cfg["organization"]

    # Carrega chaves publicas/privadas dos agentes e da empresa.
    org_private = read(base, cfg["org_private_pem_path"])
    agent_keys = {}
    identities = {}      # agent_id -> Ed25519 public PEM
    agreement_pubs = {}  # agent_id -> X25519 public PEM
    for name, info in cfg["agents"].items():
        keys = AgentKeys(
            agent_id=name,
            identity_private_pem=read(base, info["identity_private_pem_path"]),
            identity_public_pem=read(base, info["identity_public_pem_path"]),
            agreement_private_pem=read(base, info["agreement_private_pem_path"]),
            agreement_public_pem=read(base, info["agreement_public_pem_path"]),
        )
        agent_keys[name] = keys
        identities[name] = keys.identity_public_pem
        agreement_pubs[name] = keys.agreement_public_pem

    org_public = read(base, cfg["org_public_pem_path"])

    # --- Agente B (destinatario) -------------------------------------------
    agent_b = SecureAgent(
        organization=org,
        agent_id="agent-b",
        keys=agent_keys["agent-b"],
        org_agreement_pub_pem=org_public,
        org_private_pem=org_private,
        identities=identities,
        agreement_pubs=agreement_pubs,
        permissions={("agent-a", "tool", "echo"),
                     ("agent-a", "skill", "text.stats")},
        database=str(base / "agent-b.sqlite3"),
    )
    agent_b.register(Capability("tool", "echo", "Retorna o texto", echo))
    agent_b.register(Capability("skill", "text.stats", "Estatisticas", stats))

    # --- Agente A (remetente) ----------------------------------------------
    agent_a = SecureAgent(
        organization=org,
        agent_id="agent-a",
        keys=agent_keys["agent-a"],
        org_agreement_pub_pem=org_public,
        org_private_pem=None,   # A nao tem a chave de escrow
        identities=identities,
        agreement_pubs=agreement_pubs,
        permissions=set(),
        database=str(base / "agent-a.sqlite3"),
    )

    texto = "Comunicacao original entre agentes com chave da empresa."

    # A cifra para B (tool/echo).
    envelope = agent_a.encrypt_to(
        recipient_id="agent-b",
        capability={"kind": "tool", "name": "echo"},
        arguments={"text": texto},
    )
    print("=== Envelope gerado por A ===")
    print(json.dumps({k: (v[:20] + "..." if isinstance(v, str) and len(v) > 20 else v)
                      for k, v in envelope.items()}, indent=2, ensure_ascii=False))

    # B descifra e despacha (caminho normal: chave propria de B).
    resposta = agent_b.dispatch(envelope)
    print("\n=== Resposta de B ===")
    print(json.dumps(resposta, ensure_ascii=False, indent=2))
    assert resposta["result"] == {"text": texto}
    assert resposta["decrypted_via_org"] is False

    # --- Empresa descriptografa a mesma mensagem (escrow interno) ----------
    print("\n=== Empresa descriptografa via escrow ===")
    payload_empresa = agent_b.org_decrypt(envelope)
    print(json.dumps(payload_empresa, ensure_ascii=False, indent=2))
    assert payload_empresa["arguments"]["text"] == texto

    # --- Replay: mesma mensagem e rejeitada --------------------------------
    print("\n=== Teste de replay (mesma mensagem) ===")
    try:
        agent_b.dispatch(envelope)
        print("ERRO: replay nao foi rejeitado")
    except EnvelopeError as error:
        print(f"Replay rejeitado corretamente: {error.code}")
        assert error.code == "replay"

    # --- Skill via A --------------------------------------------------------
    envelope_stats = agent_a.encrypt_to(
        recipient_id="agent-b",
        capability={"kind": "skill", "name": "text.stats"},
        arguments={"text": texto},
    )
    resposta_stats = agent_b.dispatch(envelope_stats)
    print("\n=== Resultado skill text.stats ===")
    print(json.dumps(resposta_stats["result"], ensure_ascii=False))
    assert resposta_stats["result"] == {
        "words": len(texto.split()), "chars": len(texto)}

    agent_a.close()
    agent_b.close()
    print("\nDemo concluida com sucesso.")


if __name__ == "__main__":
    main()
