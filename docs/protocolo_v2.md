# Protocolo Cripto-Agent v2 — Criptografia de Mensagem com Escrow Organizacional

## Visão

O v2 mantém a identidade por certificados/TLS da v1 e adiciona **criptografia de mensagem ponta-a-ponta com escrow da empresa**.

Cada organização possui um par RSA-4096 de escrow. A chave privada fica sob guarda da empresa; a pública é distribuída a todos os agentes. Cada agente possui par RSA-2048 para identidade e assinatura.

Mensagens são:
1. Assinadas pelo remetente.
2. Criptografadas com AES-256-GCM com chave aleatória por mensagem.
3. A chave simétrica é empacotada com OAEP-SHA256 para o destinatário **e** para a empresa.

Assim, apenas o destinatário e a empresa conseguem recuperar o conteúdo. A empresa mantém capacidade de auditoria interna sem quebrar o modelo de agente-a-agente.

## Estrutura do envelope

```json
{
  "v": 2,
  "msg_id": "<uuid>",
  "org": "demo-org",
  "sender": "agent-a",
  "recipient": "agent-b",
  "issued": 1234567890,
  "expires": 1234567990,
  "nonce": "base64",
  "ciphertext": "base64",
  "keywrap_recipient": "base64",
  "keywrap_org": "base64",
  "signature": "base64"
}
```

Payload interno:
```json
{
  "sender": "...",
  "recipient": "...",
  "capability": {"kind":"tool|skill","name":"..."},
  "arguments": {...}
}
```

## Fluxo

- **Envio**: agente gera chave AES, criptografa payload, empacota chave para destinatário e empresa, assina cabeçalho.
- **Recepção**: destinatário valida assinatura, validade temporal, organização, tenta unwrap com sua chave privada; se falhar, a empresa pode unwrap com chave de escrow.
- **Autorização**: SecureAgent verifica permissões (remetente, kind, name) antes de executar handler.

## Geração de chaves

```powershell
.\.venv\Scripts\python scripts\generate_secure_keys.py --out .local\secure
```

Gera `org_private.pem`, `org_public.pem`, `agent-a_*`, `agent-b_*`.

## Exemplo rápido

```powershell
.\.venv\Scripts\python examples\secure_demo.py
```

## Propriedades de segurança

- Confidencialidade: AES-256-GCM + chave efêmera.
- Integridade/autenticidade: assinatura RSA-PSS do remetente.
- Escrow organizacional: empresa pode descriptografar qualquer mensagem com `keywrap_org`.
- Não repúdio: assinatura vincula remetente.
- Expiração curta e UUID para replay.

## Limitações

- Chaves RSA são pesadas; para produção considerar ECDH + encapsulamento.
- Key escrow centraliza poder; proteger `org_private.pem` com HSM.
- Ainda sem revogação dinâmica, rotação automática ou auditoria persistente.

## Próximos passos

- Adaptadores A2A/MCP sobre envelope seguro.
- Rotação de chaves e CRL.
- Log de auditoria imutável.
