# SELO v1 — Especificação

**Status:** rascunho de implementação (v1.0.0.dev0). **Versão do protocolo:** `selo/1`.
**URI da extensão A2A:** `https://github.com/Matheussoranco/cripto_agent/blob/main/docs/spec/selo-v1.md`.

As palavras DEVE, NÃO DEVE, DEVERIA e PODE têm o sentido de MUST, MUST NOT, SHOULD e MAY da RFC 2119. Nomes de campos, métodos e rótulos do protocolo ficam em inglês, como no A2A. O modelo de ameaça está em [`modelo-de-ameaca.md`](modelo-de-ameaca.md) e é parte normativa desta especificação: uma propriedade só é garantida contra os adversários listados lá.

## 1. Escopo e relação com o A2A

O SELO é uma **extensão do A2A 1.0**. As mensagens trocadas entre agentes são requisições e respostas JSON-RPC 2.0 do A2A 1.0, sem alteração. O SELO só muda **como** elas trafegam: dentro de um envelope cifrado e assinado (seção 7) ou de uma sessão com ratchet (seção 8), nunca em texto claro.

O A2A 1.0 renomeou os métodos da versão 0.3 usada na discussão original (issue #1). Esta especificação usa os nomes 1.0:

| A2A 0.3 (issues) | A2A 1.0 (esta spec) |
| --- | --- |
| `message/send` | `SendMessage` |
| `message/stream` | `SendStreamingMessage` |
| `tasks/get` | `GetTask` |
| `tasks/list` | `ListTasks` |
| `tasks/cancel` | `CancelTask` |
| `tasks/resubscribe` | `SubscribeToTask` |
| `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` |
| `tasks/pushNotificationConfig/get` / `list` / `delete` | `GetTaskPushNotificationConfig` / `ListTaskPushNotificationConfigs` / `DeleteTaskPushNotificationConfig` |

O SELO não implementa a semântica das tarefas: o ciclo de vida (`TASK_STATE_SUBMITTED`, `WORKING`, `COMPLETED`…) é do agente A2A que está atrás do sidecar. O SELO garante que as requisições e respostas desse ciclo chegam intactas, sigilosas, autenticadas e sem replay.

## 2. Arquitetura

```
 agente A ──(canal local)── sidecar A ════(rede: envelope/sessão)════ sidecar B ──(loopback)── agente B
```

* **Agente**: qualquer programa A2A. Não vê chaves privadas.
* **Sidecar** (`selo sidecar`): um por agente. Guarda as chaves, publica o Agent Card, cifra, decifra, verifica, aplica anti-replay, política e confiança, e persiste o estado.
* **Canal local** (seção 12): o agente fala com o próprio sidecar por named pipe (Windows) ou socket Unix (POSIX), com ACL do sistema e chave de autenticação; ou, como alternativa, HTTP em loopback com token portador.
* **Entrega local**: o sidecar entrega as requisições decifradas ao servidor A2A do agente, numa URL de loopback configurada.
* **Organização** (opcional, seção 6): âncora de confiança que atesta agentes, publica revogações e, se ligado, guarda a chave de escrow.

## 3. Primitivas e suíte

A suíte `selo/1` usa exclusivamente:

| Função | Algoritmo | Referência |
| --- | --- | --- |
| Assinatura de identidade | Ed25519 | RFC 8032 |
| Acordo de chaves | X25519 | RFC 7748 |
| Hash | SHA-256 | FIPS 180-4 |
| KDF | HKDF-SHA256 | RFC 5869 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| Cifragem de um tiro | HPKE modo base, `DHKEM(X25519, HKDF-SHA256)` (0x0020), `HKDF-SHA256` (0x0001), `ChaCha20Poly1305` (0x0003) | RFC 9180 |
| Handshake de sessão | `Noise_IK_25519_ChaChaPoly_SHA256` | Noise rev. 34 |
| Ratchet | Double Ratchet com X25519, HKDF-SHA256, HMAC-SHA256 e ChaCha20-Poly1305 | Signal, rev. 4 |
| Serialização canônica | JCS | RFC 8785 |

O identificador da suíte, `"x25519-sha256-chachapoly"`, aparece no Agent Card (`params.suite`). Um sidecar DEVE rejeitar um par cuja suíte não conhece. Segurança pós-quântica está fora da v1; uma suíte nova terá identificador novo, sem mudar o resto do protocolo.

**Implementação.** A biblioteca `cryptography` 46 não traz HPKE nem Noise. Existem bibliotecas de terceiros (`pyhpke` 0.6.5; `hpke` 0.3.2; `noiseprotocol` 0.3.1, sem release desde 2020; `dissononce` 0.34.3, sem release desde 2019; `doubleratchet` 1.3.0). A decisão (issue #1, Q19) é implementar HPKE, Noise e o ratchet sobre as primitivas da `cryptography`, sem composições novas, e validar contra os vetores oficiais: RFC 9180 (CFRG), Cacophony (Noise) e RFC 8785 (JCS). Os vetores usados estão em `tests/vectors/`.

## 4. Codificações

* **JSON canônico:** todo dado assinado ou usado como dado associado (AAD) é serializado com JCS (RFC 8785). Inteiros DEVEM estar em ±(2^53−1).
* **Binário:** base64url sem preenchimento (RFC 4648 §5), chamado `b64u` abaixo.
* **Tempo:** inteiros, segundos Unix (UTC).
* **Rótulos de domínio:** toda assinatura e derivação usa um rótulo `"selo/1/<uso>"` seguido de um byte `0x00`. Um rótulo nunca é prefixo de outro.

## 5. Identidade

### 5.1 Chaves e identificador

Cada agente tem um par **Ed25519 de identidade** e um par **X25519 de acordo**. O identificador do agente é derivado da chave de identidade **inicial** (gênese):

```
agent_id = "selo:" || b64u( SHA-256("selo/1/agent-id" || 0x00 || genesis_sig_pub)[0:24] )
```

O identificador não muda quando as chaves giram. Sem organização, ele é a única identidade (issue #1, Q8 (c)).

### 5.2 Cadeia de eventos de chave (KEL)

As chaves atuais são dadas pela **KEL**, uma lista de declarações assinadas. Cada declaração é `{"body": B, "sigs": [...]}` com assinaturas Ed25519 sobre `"selo/1/kel" || 0x00 || JCS(B)`.

| `B.t` | Campos de `B` | Assinada por |
| --- | --- | --- |
| `inception` | `seq=0`, `sig_pub`, `agree_pub`, `iat` | a própria `sig_pub` |
| `rotation` | `seq=n`, `prev` (b64u SHA-256 de `JCS(B_{n-1})`), `sig_pub`, `agree_pub`, `iat` | a chave anterior **e** a nova (prova de autoridade e de posse) |
| `revocation` | `seq=n`, `prev`, `iat` | a chave atual. Terminal: a identidade deixa de existir |

Regras:

* A KEL é verificada do início: `seq` consecutivo, `prev` correto, assinaturas válidas, `iat` não decrescente.
* **Fixação (pinning):** o sidecar guarda, por `agent_id`, o maior `seq` visto e o hash da declaração. Uma KEL nova DEVE conter a fixada como prefixo; caso contrário há bifurcação e o par é rejeitado (`kel_fork`).
* **Janela de rotação:** depois de uma `rotation` com `iat = T`, a chave anterior ainda é aceita para mensagens com `iat ≤ T + ROTATION_GRACE` e enquanto `agora ≤ T + ROTATION_GRACE` (300 s). Depois disso, só a chave nova.
* Uma identidade com `revocation` é rejeitada (`identity_revoked`).

## 6. Organizações, atestação e federação (opcional)

### 6.1 Documentos

Uma organização tem uma **âncora** Ed25519. Documentos assinados da organização têm a forma `{"body": B, "sig": b64u(Ed25519(anchor, "selo/1/<tipo>" || 0x00 || JCS(B)))}`:

* **Descritor** (`org`): `{"t":"org","name","anchor_pub","revocations_url","escrow":{"enabled":bool,"agree_pub"?},"iat"}`.
* **Atestação** (`attestation`): `{"t":"attestation","org","agent_id","roles":[...],"iat","exp"}`. Ela vai no Agent Card do agente.
* **Lista de revogação** (`revocations`): `{"t":"revocations","org","seq","iat","next_update","revoked":[agent_id,...]}`.

### 6.2 Política de confiança do sidecar

A configuração do sidecar lista as **âncoras confiáveis** (`trust.orgs`), cada uma com `name`, `anchor_pub` e `revocations_url`. Elas são configuradas pelo operador. Um sidecar NÃO DEVE aprender âncoras a partir de mensagens ou Cards de pares. A âncora da própria organização é sempre confiável.

Um par é aceito se e somente se:

1. tem uma atestação válida (assinatura, `agent_id`, `iat ≤ agora + CLOCK_SKEW < exp`) de uma organização em `trust.orgs`, **e** a lista de revogação dessa organização está fresca (`agora ≤ next_update` e `next_update − iat ≤ 24 h`) e não lista o par; ou
2. não tem atestação confiável, e `trust.allow_unattested` é verdadeiro (padrão: verdadeiro se o sidecar não pertence a uma organização, falso se pertence), e, se `trust.peers` não estiver vazio, o `agent_id` está nessa lista.

Caso contrário, o par é rejeitado (`peer_untrusted`). **Falha fechada:** se a lista de revogação de que a decisão depende não puder ser obtida ou estiver vencida, o par é rejeitado (`revocations_stale`).

**Federação** (issue #1, Q3) é o caso 1 com uma âncora de **outra** organização configurada explicitamente nos dois lados. Sem essa configuração, um agente de outra organização cai no caso 2, que é falso por padrão para quem tem organização.

**Prazos (decididos neste documento):** listas de revogação são emitidas com `next_update = iat + 3600` (1 h) por padrão; o máximo aceito é 24 h.

## 7. Agent Card

O Card é um `AgentCard` do A2A 1.0, servido em `GET <base>/.well-known/agent-card.json`, com:

* `supportedInterfaces: [{"url": <base>, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]`;
* `capabilities: {"streaming": true, "pushNotifications": true, "extensions": [X]}`, onde `X = {"uri": <URI da extensão>, "required": true, "description": "...", "params": P}`;
* `signatures: [S]`, uma assinatura JWS (RFC 7515) EdDSA destacada, como no A2A: `S.protected = b64u(JCS({"alg":"EdDSA","kid":"<agent_id>#<seq>","typ":"JOSE"}))` e `S.signature = b64u(Ed25519(sig_key, S.protected || "." || b64u(JCS(card sem "signatures"))))`.

`P` contém: `v` (`"selo/1"`), `suite`, `agent_id`, `kel`, `iat`, `exp`, `attestations` (lista, pode ser vazia), `endpoints` (`{"envelope":"/selo/v1/envelope","session":"/selo/v1/session","push":"/selo/v1/push"}`).

**Verificação.** O sidecar que busca um Card DEVE: verificar a KEL e a fixação (5.2), derivar e comparar `agent_id`, verificar a assinatura JWS com a chave de identidade atual da KEL (`kid` deve citar o `seq` atual), e exigir `iat ≤ agora + CLOCK_SKEW`, `agora < exp`, `exp − iat ≤ 7 dias` e `agora − iat ≤ max_card_age`.

**Prazos (decididos neste documento):** o Card é emitido com validade de **24 h** e reemitido na metade da validade. `max_card_age` é configurável, padrão **24 h**. Card vencido, ou mais velho que `max_card_age`, derruba a conexão (`card_stale`); não há uso de cache vencido (falha fechada, issue #1, Q13).

O Card é público e NÃO DEVE conter segredos.

## 8. Envelope de um tiro

Usado para a primeira mensagem de um par sem sessão, para métodos não streaming quando não há sessão válida, para notificações push e como recuo quando a sessão se perde.

### 8.1 Formato

```json
{"h": H, "enc": "<b64u>", "ct": "<b64u>", "sig": "<b64u>", "escrow": E}
```

`H` (cabeçalho, em claro) tem exatamente: `v` (`"selo/1"`), `t` (`"req"`, `"resp"` ou `"push"`), `sender`, `sender_card` (URL base do Card do remetente), `sender_seq`, `recipient`, `recipient_seq`, `msg` (b64u de 16 bytes aleatórios), `iat`, `exp` e, em `resp`, `re` (o `msg` respondido). `escrow` só existe quando exigido (seção 11).

### 8.2 Cifragem

```
(enc, ctx) = HPKE.SetupBaseS(pkR = agree_pub do destinatário em recipient_seq, info = "selo/1/envelope")
ct         = ctx.Seal(aad = JCS(H), pt = JCS({"rpc": <objeto JSON-RPC>}))      (ou {"push": ...})
sig        = Ed25519(sig_key do remetente em sender_seq,
                     "selo/1/envelope" || 0x00 || SHA-256(JCS(H)) || enc || SHA-256(ct) || SHA-256(JCS(E) ou ""))
```

### 8.3 Verificação (nesta ordem; qualquer falha encerra sem decifrar)

1. Forma exata, `v`, tamanho do corpo ≤ 256 KiB.
2. `recipient` é este agente e `recipient_seq` é o `seq` atual (ou o anterior, dentro da janela de rotação).
3. Tempo: `|agora − iat| ≤ CLOCK_SKEW` (120 s), `agora < exp`, `exp − iat ≤ 300 s`.
4. Card do remetente (buscado em `sender_card`): verificação da seção 7, `agent_id == sender`, política de confiança (6.2).
5. Assinatura com a chave de identidade do remetente em `sender_seq` (atual, ou anterior dentro da janela).
6. Anti-replay: o par `(sender, msg)` não pode ter sido visto; ele é guardado até `exp`, em disco.
7. `escrow` presente se exigido (seção 11).
8. `HPKE.SetupBaseR` e `Open`; o corpo decifrado deve ser JSON.

### 8.4 Transporte

`POST <base>/selo/v1/envelope` com o envelope `req`. A resposta HTTP 200 traz um envelope `resp` cifrado para o remetente (chave `agree_pub` do Card dele) e assinado pelo destinatário; o cliente verifica tudo como em 8.3, e ainda `sender == destinatário esperado` e `re == msg enviado`. Erros anteriores à autenticação são devolvidos como HTTP 4xx com `{"error": "<código>"}`, sem conteúdo, e não são autenticados.

## 9. Sessões

### 9.1 Handshake

`POST <base>/selo/v1/session` com `{"v":"selo/1","responder":<agent_id>,"responder_seq":<n>,"m1":"<b64u>"}`. O padrão é **`Noise_IK_25519_ChaChaPoly_SHA256`** (issue #1, Q9; decidido aqui, ver 17.1), com:

* `prologue = "selo/1/session" || 0x00 || JCS({"responder": <agent_id>, "responder_seq": <n>})`;
* chave estática do respondedor = `agree_pub` do Card dele em `responder_seq`; do iniciador = `agree_pub` do iniciador;
* payload de `m1` (cifrado): `JCS({"agent_id", "card": <URL base>, "seq", "iat"})`;
* payload de `m2` (cifrado): `JCS({"sid": <b64u de 16 bytes>, "exp"})`.

O respondedor DEVE: checar `iat` (±`CLOCK_SKEW`), buscar e verificar o Card do iniciador (seção 7), aplicar a política de confiança (6.2) e exigir que a chave estática recebida no handshake (`rs`) seja a `agree_pub` do iniciador em `seq`. A resposta HTTP 200 é `{"m2":"<b64u>"}`.

### 9.2 Passagem para o ratchet

Ao fim do handshake, com `ck` e `h` finais do Noise:

```
SK = HKDF-SHA256(salt = h, ikm = ck, info = "selo/1/ratchet-root", L = 32)
```

O iniciador faz `RatchetInitAlice(SK, re)`, onde `re` é a chave efêmera do respondedor no handshake. O respondedor faz `RatchetInitBob(SK, (e, re_pub))` com o próprio par efêmero do handshake. As `CipherState`s de transporte do Noise não são usadas.

### 9.3 Ratchet

Double Ratchet (Signal, rev. 4) com: `KDF_RK(rk, dh) = HKDF-SHA256(salt=rk, ikm=dh, info="selo/1/rk", L=64)`, `KDF_CK(ck) = (HMAC-SHA256(ck, 0x02), HMAC-SHA256(ck, 0x01))` (nova chave de cadeia, chave de mensagem), e, para cada chave de mensagem `mk`, `HKDF-SHA256(salt=0^32, ikm=mk, info="selo/1/mk", L=44)` → chave ChaCha20-Poly1305 (32 bytes) e nonce (12 bytes). `MAX_SKIP = 256`.

Mensagem de sessão:

```json
{"sid": "<b64u>", "hdr": {"dh": "<b64u>", "pn": 0, "n": 0}, "ct": "<b64u>", "escrow": E}
```

`AD = JCS({"sid": sid, "dir": "i2r" | "r2i"}) || JCS(hdr) || SHA-256(JCS(E) ou "")`. O texto claro é `JCS({"rpc": ...})` para requisições e respostas; em streaming, `JCS({"i": k, "event": ...})` e, no fim, `JCS({"i": k, "end": true})`.

Propriedades exigidas: cada chave de mensagem é usada uma vez e apagada (uma mensagem repetida não decifra); mensagens fora de ordem são aceitas até `MAX_SKIP`; o estado é persistido **depois de cada operação**, de modo que reiniciar o sidecar não reabre o replay.

### 9.4 Transporte

`POST <base>/selo/v1/session/<sid>` com uma mensagem de sessão (`i2r`). A resposta é uma mensagem de sessão (`r2i`, `application/json`) ou, para `SendStreamingMessage` e `SubscribeToTask`, `text/event-stream` em que cada evento `data:` é uma mensagem de sessão. O cliente DEVE exigir `i` estritamente sequencial a partir de 0 e o marcador `end` autenticado; um evento fora de ordem, repetido, adulterado, ou o fim do stream sem `end`, aborta o stream com erro.

### 9.5 Ciclo de vida

* A sessão expira em `exp` (padrão: 24 h depois do handshake) ou quando a chave de acordo de um dos lados sai da janela de rotação.
* `sid` desconhecido ou expirado → HTTP 404 `{"error":"unknown_session"}`.
* **Recuo (issue #1, Q11, ticket #12):** ao receber `unknown_session`, o cliente descarta a sessão. Se o método não é streaming, reenvia a mesma requisição por envelope (seção 8); a requisição original não foi processada, porque o servidor não a decifrou. Se é streaming, refaz o handshake e reenvia. Nada é enviado em claro.

### 9.6 Escolha do canal

| Situação | Canal |
| --- | --- |
| Método não streaming, sem sessão válida com o par | envelope; em seguida, o sidecar estabelece uma sessão para as próximas chamadas |
| Método não streaming, com sessão válida | sessão |
| `SendStreamingMessage`, `SubscribeToTask` | sessão (handshake antes, se preciso) |
| Notificação push | envelope `push` |

## 10. Notificações push

1. O agente cliente cria a configuração push (`CreateTaskPushNotificationConfig`, ou `configuration.taskPushNotificationConfig` em `SendMessage`) com a própria URL de webhook local.
2. O sidecar cliente reescreve `url` para `<base pública do cliente>/selo/v1/push/<ref>`, com `ref` aleatório de 16 bytes, e guarda `ref → (webhook local, agent_id do servidor)`. O webhook DEVE ser uma URL `http(s)` de loopback; caso contrário, o cliente recusa com `push_destination_denied`. Uma URL que já tem a forma `<base>/selo/v1/push/<ref>` (destino de terceiro) não é reescrita: quem decide é a lista de permitidos do servidor.
3. O sidecar servidor valida o destino **antes de qualquer conexão**: a URL DEVE ter a forma `<base>/selo/v1/push/<ref>`, e `<base>` DEVE ser a base do Card do próprio requisitante ou constar em `push.allowed_destinations`. Depois busca e verifica o Card em `<base>` (um destino que não é endpoint SELO é recusado). Falha → erro JSON-RPC `push_destination_denied` (−32095). Push para URL arbitrária é proibido.
4. O sidecar servidor reescreve `url` para uma URL local de entrada (`http://127.0.0.1:<porta>/push-intake/<id>`, `id` aleatório de 16 bytes) e repassa a configuração ao agente.
5. Quando o agente servidor faz o POST da notificação na URL local, o sidecar a envia como envelope `push` (`{"push": {"ref", "token", "payload"}}`) para `<base>/selo/v1/push/<ref>`.
6. O sidecar cliente verifica o envelope (8.3), exige `sender ==` o `agent_id` guardado para `ref`, entrega `payload` ao webhook local, com o token original no cabeçalho `X-A2A-Notification-Token`, e responde com um envelope `resp` (`{"ack": <status HTTP do webhook>}`).

As respostas de `GetTaskPushNotificationConfig` e `ListTaskPushNotificationConfigs` mostram a URL de entrada local do servidor, não o webhook original do cliente.

Relay para agentes atrás de NAT está fora da v1: o destino precisa ser alcançável.

## 11. Escrow organizacional (opcional)

Desligado por padrão. Só se aplica quando **remetente e destinatário** têm atestação válida da **mesma** organização O, e o descritor de O configurado localmente diz `escrow.enabled = true`. O escrow de uma organização nunca vale para mensagens com outra (issue #1, Q2).

Nesse caso a mensagem DEVE levar `escrow = {"org": O, "enc": "<b64u>", "ct": "<b64u>"}`, que é `HPKE.SealBase(pk = escrow.agree_pub de O, info = "selo/1/escrow", aad = SHA-256(dado associado da mensagem), pt = material)`, onde `material` é, no envelope, `key || base_nonce` do contexto HPKE; na sessão, a chave de mensagem `mk`. A assinatura (envelope) ou o AD (sessão) cobrem `escrow`. O receptor rejeita mensagem sem `escrow` quando ele é exigido (`escrow_required`).

A chave privada de escrow deriva da semente mestra da organização (`HKDF(master, info="selo/1/escrow-key")`), que pode ser dividida por Shamir. Cada leitura auditada exige auditor e motivo e é registrada num log encadeado por hash. **Limite:** o receptor não consegue verificar que o `escrow` decifra para o material correto; um remetente malicioso pode inutilizá-lo. O escrow serve para auditar agentes honestos da própria organização, não para detectar agentes maliciosos.

## 12. Canal local (agente ↔ sidecar)

### 12.1 Pipe ou socket (padrão)

* Windows: named pipe `\\.\pipe\selo-<nome>`; POSIX: socket Unix num diretório `0700`, socket `0600`.
* Autenticação: além da ACL do sistema, um desafio HMAC com uma chave de 32 bytes guardada em arquivo legível só pelo usuário (`multiprocessing.connection`, `authkey`).
* Quadros JSON (`send_bytes`/`recv_bytes`; nunca pickle): `{"op":"call","peer":R,"rpc":{...}}` → `{"rpc":{...}}`; `{"op":"stream","peer":R,"rpc":{...}}` → `{"event":{...}}`… seguido de `{"end":true}`; `{"op":"card","peer":R}`; `{"op":"whoami"}`. Erros: `{"error":{"code","message"}}`.

### 12.2 HTTP em loopback (alternativa)

Ouve só em `127.0.0.1`, exige `Authorization: Bearer <token>` (32 bytes aleatórios em arquivo legível só pelo usuário), e expõe uma interface compatível com A2A por par: `POST /peers/<R>/` (JSON-RPC; SSE para métodos de streaming) e `GET /peers/<R>/.well-known/agent-card.json` (o Card do par verificado, com a URL reescrita para este endereço local). Assim um cliente A2A comum funciona apontando para o sidecar.

`R` é um apelido configurado em `peers` ou a URL base do par codificada (percent-encoding).

### 12.3 Entrega ao agente

O sidecar entrega as requisições decifradas por `POST` à URL de loopback do servidor A2A do agente (`agent.url`), com os cabeçalhos `X-Selo-Sender: <agent_id>`, `X-Selo-Org: <organização atestada ou vazio>`, `A2A-Version: 1.0` e, se configurado, `Authorization: Bearer <agent.inbound_token>`.

O agente nunca recebe chaves. Um agente comprometido pode pedir envios ao sidecar, mas não consegue extrair a identidade.

## 13. Transporte HTTP e TLS

| Rota pública | Uso |
| --- | --- |
| `GET /.well-known/agent-card.json` | Agent Card |
| `POST /selo/v1/envelope` | envelope de um tiro |
| `POST /selo/v1/session` | handshake |
| `POST /selo/v1/session/<sid>` | mensagem de sessão |
| `POST /selo/v1/push/<ref>` | notificação push (envelope `push`) |
| qualquer outro `POST` | JSON-RPC em claro: recusado com `extension_required` (−32090) e `data.extension = <URI>` |

**TLS é obrigatório fora do loopback** (issue #1, Q7). O sidecar DEVE recusar subir em endereço que não seja de loopback sem certificado e chave TLS, e DEVE recusar contatar uma URL `http://` cujo host não seja de loopback (`127.0.0.0/8`, `::1`, `localhost`). Certificados são verificados pelo repositório do sistema ou por uma CA configurada; certificado inválido faz o envio falhar. O envelope é a garantia de segurança; o TLS esconde o cabeçalho (`sender`, `recipient`) de observadores da rede.

Limite de corpo: 256 KiB.

## 14. Estado e chaves

* Estado em SQLite, no diretório de estado, com esquema versionado (`meta.schema_version = 1`): anti-replay, sessões, fixações de KEL, mapeamentos de push.
* O estado das sessões é cifrado (ChaCha20-Poly1305) com uma chave de dados.
* Chaves privadas (identidade, acordo, chave de dados) ficam no cofre do sistema: DPAPI (Windows), Keychain (`security`, macOS) ou Secret Service (`secret-tool`, Linux). Alternativa: arquivo cifrado por senha (scrypt + ChaCha20-Poly1305), com a senha em `SELO_KEY_PASSWORD` ou digitada. Chaves privadas nunca ficam em texto claro no disco.

## 15. Gancho de política

A configuração pode apontar `policy` para um chamável `módulo:função`. Ele recebe um `PolicyEvent` (`direction`: `inbound`/`outbound`; `stage`: `request`/`response`; `peer_id`; `peer_org`; `method`; `rpc`, uma cópia) e devolve `None` para permitir ou levanta `PolicyDenied(reason)`. Uma recusa vira o erro JSON-RPC `policy_denied` (−32093). O evento não dá acesso a chaves nem ao sidecar. Sem gancho, nada muda. A defesa contra injeção de prompt (protótipo `selo_v0`) será um pacote opcional que usa este gancho.

## 16. Constantes e erros

| Constante | Valor |
| --- | --- |
| `CLOCK_SKEW` | 120 s |
| Validade do envelope (`exp − iat`) | padrão 60 s, máximo 300 s |
| `ROTATION_GRACE` | 300 s |
| Validade do Card | 24 h (máximo 7 d) |
| `max_card_age` | configurável, padrão 24 h |
| Lista de revogação | `next_update` padrão 1 h, máximo 24 h |
| Validade da sessão | 24 h |
| `MAX_SKIP` | 256 |
| Corpo máximo | 256 KiB |

| Código | JSON-RPC | Significado |
| --- | --- | --- |
| `extension_required` | −32090 | requisição A2A em claro num endpoint SELO |
| `unknown_session` | −32091 / HTTP 404 | sessão desconhecida ou expirada |
| `policy_denied` | −32093 | recusa do gancho de política |
| `peer_untrusted` | −32094 | par fora da política de confiança |
| `push_destination_denied` | −32095 | destino push recusado |
| `card_stale`, `kel_fork`, `identity_revoked`, `peer_revoked` (revogado pela organização), `bad_attestation`, `bad_org_doc`, `revocations_stale`, `bad_signature`, `bad_ciphertext`, `replay`, `invalid_lifetime`, `wrong_recipient`, `escrow_required` | HTTP 4xx | falhas de verificação |

## 17. Decisões registradas

### 17.1 Noise IK, e não XX

O iniciador sempre conhece a chave estática do respondedor antes de falar com ele (está no Card). Com IK, o handshake tem uma ida e volta, a primeira mensagem já autentica o respondedor e a identidade do iniciador vai cifrada. XX custaria uma ida e volta a mais e protegeria a identidade do respondedor, que já é pública no Card. Limite conhecido do IK: a mensagem 1 pode ser repetida por um atacante; isso só cria uma sessão do lado do respondedor que o atacante não consegue usar, porque não tem a chave efêmera do iniciador, e o payload de `m1` não carrega requisição.

### 17.2 Prazos

Card: 24 h de validade, `max_card_age` 24 h. Lista de revogação: 1 h, máximo 24 h. Janela de rotação: 300 s. Sessão: 24 h. Esses valores fecham os pontos `Unresolved` da issue #1.

### 17.3 Criptografia sobre a `cryptography`

Ver seção 3.

## 18. Vetores de teste

* Oficiais: `tests/vectors/hpke_base_x25519_sha256_chachapoly.json` (RFC 9180), `tests/vectors/noise_cacophony_25519_chachapoly_sha256.json` (Cacophony), `tests/vectors/jcs_rfc8785_numbers.json` e `tests/vectors/jcs_cyberphone_testdata.json` (RFC 8785).
* Próprios do SELO (`tests/vectors/selo_v1.json`, gerados por `tests/vectors/make_selo_vectors.py` com chaves e aleatoriedade fixas): `agent_id`, KEL, assinatura do Card, envelope, handshake + passagem para o ratchet, primeiras mensagens do ratchet. Uma implementação independente deve reproduzi-los byte a byte.
