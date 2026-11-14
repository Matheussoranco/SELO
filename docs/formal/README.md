# Modelo formal do handshake (ticket #11)

`noise_ik_selo.pv` modela em ProVerif o handshake de sessão do SELO, `Noise_IK_25519_ChaChaPoly_SHA256`, seguido da derivação da raiz do ratchet (especificação, seção 9). O atacante é Dolev-Yao, cobrindo os adversários A1 e A2 do [modelo de ameaça](../spec/modelo-de-ameaca.md): lê, altera, repete e injeta mensagens, tem identidade própria e abre sessões com os agentes honestos. Na fase 1, as chaves estáticas dos dois agentes honestos vazam, para testar o sigilo progressivo.

## Status: modelo escrito, verificação NÃO executada

O modelo não foi verificado nesta sessão de desenvolvimento. Os motivos:

* a WSL da máquina de desenvolvimento estava sem DNS, então `apt install proverif` não pôde ser instalado;
* o binário oficial para Windows (`proverifbin2.05.tar.gz`, do site da INRIA, SHA-256 `7b402ce0…0a32`) foi baixado, mas a execução de um binário baixado foi bloqueada pela política de permissões da sessão.

Portanto, **nenhuma das propriedades abaixo está provada por ferramenta até alguém rodar o modelo.** A coluna "esperado" registra o que a análise manual prevê, não um resultado.

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
