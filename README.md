# SELO

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

**SELO é uma extensão do protocolo A2A com criptografia de ponta a ponta nativa.** Agentes conversam por mensagens, tarefas, streaming e notificações push do A2A 1.0, e tudo que passa pela rede vai cifrado e assinado. Funciona entre agentes na mesma máquina, numa intranet ou pela internet.

* **Sigilo de ponta a ponta por padrão.** Só o destinatário lê. Uma organização pode, opcionalmente, ler mensagens entre os próprios membros (escrow auditado).
* **Identidade própria do agente.** Cada agente tem uma chave Ed25519 e um `agent_id` derivado dela, que não muda quando as chaves giram. Organização é opcional.
* **Compatível com A2A.** O Agent Card é um card A2A 1.0 com a extensão SELO, e as mensagens são o JSON-RPC do A2A dentro do envelope. Um cliente A2A comum funciona apontando para o sidecar local.
* **Uma dependência de execução:** `cryptography`. HPKE (RFC 9180), Noise IK e Double Ratchet são implementados sobre ela e validados contra os vetores oficiais.

> **Status: 1.0.0.dev0, prova de conceito avançada, não auditada.** Veja [o que foi e o que não foi validado](#validação). Não use para proteger dados reais sem revisão independente.

## Como funciona

```
 agente A ──(canal local)── sidecar A ═══(HTTPS: envelope HPKE / sessão Noise IK + ratchet)═══ sidecar B ──(loopback)── agente B
```

* Cada agente roda ao lado de um **sidecar** (`selo sidecar`). O sidecar guarda as chaves no cofre do sistema e publica o **Agent Card** assinado. Ele também cifra, verifica e aplica anti-replay e a política de confiança, e entrega as requisições decifradas ao servidor A2A do agente.
* O agente fala com o próprio sidecar por **named pipe** (Windows) ou **socket Unix** (POSIX), com ACL do sistema e desafio HMAC. A alternativa é HTTP em loopback com token. O agente nunca vê as chaves.
* A primeira mensagem para um par vai num **envelope** de um tiro: HPKE para a chave do destinatário, mais a assinatura Ed25519 do remetente. Em seguida o sidecar abre uma **sessão** (handshake Noise IK seguido de Double Ratchet) para as próximas chamadas, tarefas e streaming. Se a sessão se perde, o sidecar volta ao envelope sem expor conteúdo.
* Fora do loopback, **TLS é obrigatório**: o sidecar não sobe e não contata `http://` remoto.

A especificação completa está em [`docs/spec/selo-v1.md`](docs/spec/selo-v1.md), o modelo de ameaça em [`docs/spec/modelo-de-ameaca.md`](docs/spec/modelo-de-ameaca.md) e o glossário em [`CONTEXT.md`](CONTEXT.md).

## Instalação

Requer Python 3.11+.

```sh
python -m venv .venv
.venv/bin/python -m pip install -e .             # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pip install -e ".[interop]"  # opcional: a2a-sdk, só para os testes de interoperabilidade
```

## Início rápido (dois agentes na mesma máquina)

```sh
# dois agentes A2A de referência (qualquer servidor A2A 1.0 serve)
python -m selo.refagent --name alice --port 9101 &
python -m selo.refagent --name bob   --port 9102 &

# um sidecar para cada um
selo init --config alice.json --name alice --agent-url http://127.0.0.1:9101/ --port 8101
selo init --config bob.json   --name bob   --agent-url http://127.0.0.1:9102/ --port 8102
selo sidecar --config alice.json &      # imprime READY {"agent_id": ..., "public_url": ...}
selo sidecar --config bob.json &

# alice manda uma mensagem para bob, pelo canal local do próprio sidecar
selo send --config alice.json --peer http://127.0.0.1:8102 --text "olá, bob"
selo whoami --config alice.json
```

Na primeira execução, cada sidecar gera a identidade e a guarda no cofre do sistema: DPAPI no Windows, Keychain no macOS, Secret Service no Linux. Sem cofre do sistema, use `--keystore file` e defina `SELO_KEY_PASSWORD`.

### De um programa

```python
from selo.local import LocalClient

client = LocalClient("alice-state")      # o state_dir do sidecar
resp = client.call("http://127.0.0.1:8102", {
    "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
    "params": {"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "oi"}]}},
})
for event in client.stream("http://127.0.0.1:8102", {...}):   # SendStreamingMessage / SubscribeToTask
    ...
```

Com `"local": {"mode": "http"}`, o sidecar expõe `http://127.0.0.1:<porta>/peers/<par>/` como um endpoint A2A comum, com `Authorization: Bearer <token>` (o token fica em `<state_dir>/run/local.token`). O `a2a-sdk` oficial funciona apontando para essa URL; isso é testado.

### Entre máquinas

Use `--host <ip> --tls-cert cert.pem --tls-key key.pem` no `selo init`. Os pares precisam confiar no certificado: CA pública, ou `"tls": {"ca_file": ...}` na configuração.

### Organizações (opcional)

```sh
selo org init --dir acme --name acme --revocations-url https://org.acme.example/revocations [--escrow]
selo org serve --dir acme --host 0.0.0.0 --port 9443 --tls-cert ... --tls-key ...
selo org attest --dir acme --agent-id selo:...       # atestação para a configuração do agente
selo org revoke --dir acme --agent-id selo:...
selo org anchor --dir acme                           # o que outra organização põe em trust.orgs
selo org audit  --dir acme --capture captura.jsonl --auditor fulana --reason "incidente 42"
```

A configuração do sidecar recebe `"org": {"descriptor": ..., "attestation": ...}`. Um membro de organização só aceita outros membros e as âncoras configuradas em `trust.orgs`. A federação é sempre explícita, nos dois lados. Se a lista de revogação vencer, o sidecar recusa a conexão.

## Validação

| O quê | Resultado |
| --- | --- |
| Suíte de testes no Windows 11 (Python 3.13.5, `cryptography` 46.0.7, DPAPI, named pipe) | **206 testes, todos aprovados** (102 do SELO v1 e 104 do protótipo v0); 1 pulado (teste opcional na interface de rede) |
| A mesma suíte no Linux (WSL2, Python 3.12.3, `cryptography` 41.0.7, socket Unix, cofre em arquivo) | **206 testes, todos aprovados**; 6 pulados (DPAPI, `a2a-sdk` não instalado, interface de rede) |
| Vetores oficiais | HPKE RFC 9180 (chaves, segredo, 257 cifragens, exports), Noise Cacophony (IK, XX, NN, N: 24 mensagens), JCS RFC 8785 (26 números + casos de referência). Todos conferem |
| Vetores próprios | `tests/vectors/selo_v1.json` é reproduzido byte a byte no Windows e no Linux |
| Interoperabilidade com o `a2a-sdk` 1.3.0 | O agente servidor do SDK atrás do SELO, o cliente do SDK pelo canal local, o SDK lendo o Agent Card do SELO e o erro definido para clientes sem a extensão. Todos passam |
| Dois hosts em redes separadas, com falhas injetadas ([`docs/validacao/duas-maquinas.json`](docs/validacao/duas-maquinas.json)) | **19 de 19 verificações**. Ver abaixo |

**Dois hosts** (`tests/twohost/scenario.py`, 18/11/2026). A reexecução usou Python 3.12.3 e `cryptography` 46.0.7, dentro da faixa de dependências do projeto. O relatório registra a revisão testada. Três namespaces de rede no mesmo kernel WSL2 (6.18.58.1) isolaram host-a `10.10.1.2/24`, roteador e host-b `10.10.2.2/24`. O cenário usou HTTPS sob uma CA de teste e uma lista de revogação servida do host-a. O roteiro verificou o seguinte:

* mensagem, tarefa longa, cancelamento, streaming SSE e push entre os hosts;
* rotação de chaves;
* replay e adulteração de envelope rejeitados;
* mensagem de sessão antiga (reordenada) e adulterada rejeitadas;
* relógio adiantado em 10 min rejeitado. O código observado foi `revocations_stale`: a lista de revogação parece vencida para quem está adiantado, e essa checagem vem antes da janela do envelope;
* Card vencido derruba a conexão (`card_stale`), e o par se recupera ao corrigir o relógio;
* lista de revogação vencida que não pôde ser atualizada: a conexão falha fechada;
* agente revogado pela organização rejeitado (`peer_revoked`);
* as capturas de rede não contêm texto claro.

**O que NÃO foi validado:**

* **Máquinas físicas distintas ou internet real.** Os "dois hosts" são namespaces de rede no mesmo kernel; isso prova a separação de pilhas de rede e o roteamento, não latência, NAT ou firewalls reais. Agentes atrás de NAT não são suportados na v1 (não há relay).
* **Modelo formal:** a execução do modelo do handshake no ProVerif 2.05 ([`docs/formal/`](docs/formal/README.md)) atingiu o limite de tempo sem emitir nenhum veredito. As propriedades listadas lá são análise manual, não prova.
* **Cofres Keychain (macOS) e Secret Service (Linux):** implementados pela interface das ferramentas do sistema, nunca executados. DPAPI e o cofre em arquivo são testados.
* Nenhuma auditoria criptográfica independente. Sem medição de desempenho, sem proteção contra negação de serviço, sem resistência a canais laterais de tempo.

## Testes

```sh
python -m unittest discover -s tests -t .                 # toda a suíte (inclui o protótipo v0)
python tests/vectors/make_selo_vectors.py                  # regenera os vetores próprios
sudo python3 tests/twohost/scenario.py --out relatorio.json # dois hosts (Linux, root, iproute2)
SELO_TEST_LAN=1 python -m unittest tests.test_tls          # inclui o teste na interface de rede
docker build -t selo . && docker run --rm selo             # suite num Linux limpo (Dockerfile não executado nesta revisão)
```

Os testes de ponta a ponta sobem processos reais (agentes, sidecars e um proxy que grava, adultera, descarta e reordena tráfego) e falam com eles só pela rede ou pelo canal local. Os testes que dependem de tempo usam um relógio injetável.

## Estrutura

| Caminho | Conteúdo |
| --- | --- |
| `selo/crypto/` | HPKE, Noise, Double Ratchet e primitivas |
| `selo/identity.py`, `card.py` | `agent_id`, KEL (rotação/revogação) e Agent Card assinado |
| `selo/envelope.py`, `sessions.py`, `channel.py` | envelope de um tiro, sessões e regra de canal |
| `selo/sidecar.py`, `local.py`, `net.py` | sidecar, canal local, HTTP/TLS e SSE |
| `selo/peers.py`, `org.py`, `escrow.py`, `policy.py`, `push.py` | confiança, organizações, escrow, gancho de política, push |
| `selo/store.py`, `keystore.py`, `config.py` | estado em SQLite e cofre de chaves |
| `selo/refagent.py` | agente A2A de referência (testes e demonstração) |
| `docs/spec/`, `docs/formal/`, `docs/validacao/` | especificação, modelo de ameaça, modelo ProVerif, resultados |
| `selo_v0/`, `tests/v0/`, `experiments/`, `docs/selo_v0.md` | protótipo anterior (proveniência, manifestos, linter MCP), base do futuro pacote opcional de defesa contra injeção de prompt |

## Licença

Copyright (c) 2025-2026 Matheus Soranço. Licenciado sob a **Creative Commons Atribuição-NãoComercial-CompartilhaIgual 4.0 Internacional** (SPDX: `CC-BY-NC-SA-4.0`). O texto legal está em [`LICENSE`](LICENSE).

Em resumo (o texto legal prevalece): você pode copiar, adaptar e redistribuir, com atribuição, apenas para fins não comerciais, e adaptações devem usar a mesma licença. A licença não concede direitos de patente nem de marca. O GitHub exibe "NOASSERTION" porque seu detector não reconhece licenças Creative Commons NonCommercial.
