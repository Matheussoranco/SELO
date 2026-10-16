# Protocolo Chave-Organizacao v3

Protocolo original de comunicacao entre agentes de uma organizacao, com
criptografia de mensagem ponta-a-ponta e **escrow organizacional**: a empresa
possui uma chave de descriptografia para seguranca interna / auditoria.

O protocolo e independente de transporte: o envelope e um JSON autocontido que
pode viajar por HTTP/HTTPS, filas, mensageria ou qualquer canal de rede. A
confidencialidade vem da camada da mensagem, nao do canal.

---

## 1. Estrutura de chaves (original)

Cada participante gerencia chaves independentes de maquina e de perfil do SO:

| Chave | Algoritmo | Uso | Quem guarda |
|-------|-----------|-----|-------------|
| Identidade do agente | Ed25519 | Assinar mensagens (autenticidade / nao-repudio) | O proprio agente |
| Acordo do agente | X25519 | Derivacao de chave simétrica para cifrar para esse agente | O proprio agente |
| Escrow da organizacao | X25519 | Recuperar a chave simetrica de qualquer mensagem | Somente a empresa |

A chave privada de escrow permanece sob guarda da empresa (idealmente HSM).
A publica de escrow e a publica de acordo/identidade de cada agente sao
distribuidas aos agentes da organizacao por cadastro administrativo.

---

## 2. Formato do envelope (v3)

```json
{
  "v": 3,
  "msg_id": "<uuid4>",
  "org": "demo-org",
  "sender": "agent-a",
  "recipient": "agent-b",
  "issued": 1729000000,
  "expires": 1729000060,
  "sender_x25519_pub": "<base64 32 bytes>",
  "capability": {"kind": "tool|skill", "name": "..."},
  "nonce": "<base64 12 bytes>",
  "ciphertext": "<base64>",
  "wrap_recipient": "<base64>",
  "wrap_org": "<base64>",
  "signature": "<base64 64 bytes>"
}
```

Campos `capability` sao metadados de roteamento (nao secretos). O restante do
conteudo de negocios fica cifrado.

Payload interno (cifrado, JSON):
```json
{
  "sender": "agent-a",
  "recipient": "agent-b",
  "capability": {"kind":"tool","name":"echo"},
  "arguments": {"text": "..."}
}
```

---

## 3. Fluxo de criptografia (envio)

1. Gera um par X25519 efemero do remetente para esta mensagem.
2. Monta o cabeceario de roteamento (`v` ... `capability`).
3. Gera chave simetrica aleatoria `K` (AES-256) e nonce de 12 bytes.
4. Cifra o payload com **AES-256-GCM**, autenticado ao cabeceario de roteamento
   (AAD).
5. Faz ECDH do par efemero com a chave X25519 de acordo do **destinatario** e
   deriva `K_rec` via HKDF-SHA256 (`org-chave/recipient/v3`).
6. Faz ECDH do par efemero com a chave X25519 de **escrow** da empresa e deriva
   `K_org` via HKDF-SHA256 (`org-chave/escrow/v3`).
7. Encapsula `K` duas vezes com AES-256-GCM: `wrap_recipient` e `wrap_org`
   (cada um com seu proprio nonce prependido).
8. Assina o cabeceario completo (incluindo ambos os wraps) com a chave Ed25519
   do remetente.

Resultado: apenas o destinatario (via `K_rec`) e a empresa (via `K_org`)
recuperam `K` e, portanto, o payload.

---

## 4. Fluxo de recepcao (destinatario)

1. Valida campos obrigatorios, versao `3`, organizacao e janela temporal
   (emissao e expiracao com tolerancia de relogio).
2. Verifica a assinatura Ed25519 usando a chave de identidade cadastrada do
   remetente.
3. Tenta recuperar `K` com sua propria chave X25519 (`wrap_recipient`).
4. Se falhar e a chave privada de escrow da empresa estiver disponivel, recupera
   `K` via `wrap_org` (marca `decrypted_via_org = true`).
5. Descifra o payload com `K` e valida remetente/destinatario/capacidade
   contra o envelope.
6. Consulta o registro persistente de `msg_id` (SQLite): rejeita replay.
7. Verifica permissao `(remetente, kind, name)` (negar por padrão).
8. Executa o handler da tool/skill e retorna o resultado.

---

## 5. Seguranca interna da empresa (escrow)

A empresa pode descriptografar qualquer mensagem da organizacao usando a
chave privada de escrow e a chave de identidade publica do remetente
(`org_decrypt_message`). Isso permite auditoria interna sem quebrar o modelo
agente-a-agente: o destinatario ainda detecta quando a empresa precisou
intervir (`decrypted_via_org`).

Propriedades:
- Confidencialidade: AES-256-GCM com chave efemera por mensagem.
- Autenticacao / nao-repudio: assinatura Ed25519 do remetente.
- Integridade do cabeceario: assinatura cobre ambos os encapsulamentos.
- Escrow organizacional: empresa descriptografa qualquer mensagem.
- Replay e expiracao: UUID persistente + janela temporal curta.
- Autorizacao: negar por padrão, permissao explicitas por agente.

---

## 6. Limites

- Prototipo experimental; nao substitui analise de seguranca de producao.
- Chaves privadas nao estao protegidas por senha nesta versao; em producao
  proteger o `org_private.pem` com HSM/ACLs rigorosas.
- Sem rotacao automatica, revocacao ou CRL de chaves.
- Sem isolamento de handler nem limites de concorrencia de producao.
- A identidade e a chave de escrow sao fronteiras de confidencia: comprometer
  a chave de escrow expõe todo o trafego historico/futuro cifrado com ela.

---

## 7. Execucao

```powershell
cd C:\Users\mathe\Documents\Code\cripto_agent
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python scripts\generate_chave_keys.py --out .local\chave
.\.venv\Scripts\python examples\chave_demo.py
.\.venv\Scripts\python -m unittest discover -s tests -v
```

O `chave_demo.py` mostra: A cifra para B, B executa, a empresa descriptografa
via escrow e o replay e rejeitado.

---

## Relacionamento com versoes anteriores

- v1: HTTPS/mTLS, identidade por certificado, transporte cifrado.
- v2: adiciona criptografia de mensagem com escrow RSA (RSA-4096 org + RSA-2048 agentes).
- v3 (este documento): protocolo original com X25519/Ed25519, encapsulamento duplo
  HKDF(X25519), assinatura Ed25519 e escrow da empresa. Transporte independente.

Nenhuma implementa A2A nem MCP nativamente; adaptadores sao evolucao prevista.
