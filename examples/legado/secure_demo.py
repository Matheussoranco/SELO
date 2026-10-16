"""Exemplo de uso do protocolo seguro v2."""
import json
from pathlib import Path
from cripto_agent.legado.secure_protocol import AgentKeys, SecureAgent, Capability, encrypt_message, decrypt_message

def echo(args):
    return {"text": args["text"]}

def stats(args):
    t = args["text"]
    return {"words": len(t.split()), "chars": len(t)}

def main():
    base = Path(".local/secure")
    cfg = json.loads((base / "config.json").read_text())
    org_pub = (base / cfg["org_public_pem_path"]).read_text()
    # carregar chaves
    a_keys = AgentKeys(private_pem=(base / "agent-a_private.pem").read_text(),
                       public_pem=(base / "agent-a_public.pem").read_text())
    b_keys = AgentKeys(private_pem=(base / "agent-b_private.pem").read_text(),
                       public_pem=(base / "agent-b_public.pem").read_text())

    # agentes
    agent_b = SecureAgent("demo-org", "agent-b", b_keys, org_pub, permissions={("agent-a","tool","echo"),("agent-a","skill","text.stats")})
    agent_b.register(Capability("tool","echo","Echo", echo))
    agent_b.register(Capability("skill","text.stats","Stats", stats))

    payload = {
        "sender": "agent-a",
        "recipient": "agent-b",
        "capability": {"kind":"skill","name":"text.stats"},
        "arguments": {"text":"Olá do agente A"}
    }
    envelope = encrypt_message(
        organization="demo-org",
        sender_id="agent-a",
        recipient_id="agent-b",
        sender_keys=a_keys,
        recipient_pub_pem=b_keys.public_pem,
        org_pub_pem=org_pub,
        payload=payload
    )
    print("Envelope gerado:", json.dumps(envelope, indent=2)[:500])

    # agente B processa
    result = agent_b.dispatch_secure(envelope, sender_pub_pem=a_keys.public_pem)
    print("Resultado:", result)

    # empresa pode descriptografar usando chave privada da org
    # org_priv = ... (apenas demonstração)
    # payload2, via_org = decrypt_message(envelope, b_keys, org_private_pem=..., expected_org="demo-org", expected_sender_pub_pem=a_keys.public_pem)

if __name__ == "__main__":
    main()
