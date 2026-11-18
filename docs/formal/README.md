# Modelo formal do handshake (ticket #11)

`noise_ik_selo.pv` modela em ProVerif o handshake de sessão do SELO, `Noise_IK_25519_ChaChaPoly_SHA256`, seguido da derivação da raiz do ratchet (especificação, seção 9). O atacante é Dolev-Yao, cobrindo os adversários A1 e A2 do [modelo de ameaça](../spec/modelo-de-ameaca.md): lê, altera, repete e injeta mensagens, tem identidade própria e abre sessões com os agentes honestos. Na fase 1, as chaves estáticas dos dois agentes honestos vazam, para testar o sigilo progressivo.

## Status: execução inconclusiva

Em 18/11/2026, às 20:19:23 UTC, o binário oficial do ProVerif 2.05 para Windows foi executado sobre o modelo da revisão `62a7b7864dd4fee67b9787cf87dde4b0930e62b3`. O arquivo `proverifbin2.05.tar.gz` usado tinha SHA-256 `7b402ce05343e8819c8f05b871105c06d96d5c86556035fa3db4ad24c0820a32`.

Após 180 segundos, a execução foi interrompida por tempo limite (código 124 do executor), ainda durante a saturação: a última linha do log registrava 18.200 regras inseridas. O verificador não emitiu nenhuma linha `RESULT`. **Q1–Q7 continuam sem veredito.** O tempo limite não é prova, refutação ou demonstração de que o modelo nunca termina. A coluna "esperado" registra a análise manual, não um resultado do verificador.

## Como rodar

```sh
opam install proverif            # ou o binário oficial: https://bblanche.gitlabpages.inria.fr/proverif/install.html
proverif docs/formal/noise_ik_selo.pv | grep RESULT
```

## Consultas

| # | Propriedade | Esperado | Por quê |
| --- | --- | --- | --- |
| Q1 | Raiz do ratchet de sessão honesta secreta, inclusive após o vazamento das chaves estáticas | verdadeira | `ee` e `se` usam as chaves efêmeras, que não vazam |
| Q2 | Payload de `m2` secreto após o vazamento | verdadeira | idem (chave depois de `ee`/`se`) |
| Q3 | Payload de `m1` secreto antes do vazamento | verdadeira | `es` + `ss` com chaves não comprometidas |
| Q4 | Payload de `m1` secreto **após** o vazamento | **falsa** (ataque esperado) | `m1` só depende de `es` e `ss`; quem obtiver depois a chave do respondedor recalcula as duas. Por isso o SELO só põe em `m1` dados não secretos (`agent_id`, URL do Card, `seq`, `iat`) |
| Q5 | Autenticação injetiva do respondedor perante o iniciador | verdadeira | `es`/`se` exigem a chave privada do respondedor; o efêmero do respondedor é novo a cada sessão |
| Q6 | Autenticação (não injetiva) do iniciador perante o respondedor | verdadeira | `ss` e a chave estática cifrada em `m1` exigem a chave privada do iniciador |
| Q7 | Autenticação **injetiva** do iniciador | **falsa** (ataque esperado) | `m1` pode ser repetida; o respondedor aceita de novo. A sessão repetida é inútil para o atacante (Q1); risco residual registrado no modelo de ameaça |

## O que o modelo não cobre

* A ligação entre chave estática e `agent_id` pelo Agent Card assinado e pela KEL (seções 5 e 7). Ela é coberta por testes, não por prova.
* O Double Ratchet depois do handshake, o envelope HPKE, o escrow e a política de confiança.
* Detalhes de nonce (no handshake do Noise cada chave cifra uma única vez, com nonce 0) e o comprimento das mensagens.
* Ataques de implementação (canais laterais, erros de parsing), que os testes e os vetores de teste cobrem em parte.
