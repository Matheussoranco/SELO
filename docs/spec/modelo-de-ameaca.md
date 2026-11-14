# SELO v1 — Modelo de ameaça

Este documento é citado pela [especificação](selo-v1.md) e define contra quem as garantias valem. Uma propriedade que não aparece aqui não é garantida.

## Ativos

* Conteúdo das mensagens A2A (requisições, respostas, eventos de streaming, notificações push).
* Integridade e ordem dessas mensagens.
* Identidade dos agentes (chaves privadas Ed25519 e X25519) e a chave de dados do estado.
* Decisões de confiança: quem é aceito como par, e de qual organização.

## Adversários

| # | Adversário | Capacidades | O que o SELO garante contra ele |
| --- | --- | --- | --- |
| A1 | **Observador passivo da rede** | Lê todo o tráfego | Sigilo do conteúdo (HPKE / Noise + ratchet). Com TLS, também o cabeçalho do envelope. Sigilo progressivo das sessões: comprometer depois as chaves de longo prazo não revela mensagens de sessão já trocadas. |
| A2 | **Atacante ativo na rede** | Lê, altera, descarta, repete, reordena e injeta mensagens; se passa por qualquer servidor HTTP | Integridade e autenticidade (assinatura, AEAD, AD). Repetição rejeitada (anti-replay persistente, chaves de ratchet de uso único). Reordenação: aceita no ratchet até `MAX_SKIP`, rejeitada nos streams (índice estritamente sequencial e marcador `end` autenticado). Truncamento de stream detectado. Não pode substituir o Card de um par fixado (KEL e fixação). Descarte e atraso continuam possíveis (disponibilidade não é garantida). |
| A3 | **Agente par malicioso e autenticado** | Possui a própria identidade válida; envia o que quiser | Não consegue se passar por outro agente, repetir mensagens de terceiros, nem ler mensagens que não lhe foram enviadas. Push só para destinos permitidos. **Não** é impedido de mentir no conteúdo, de vazar o que recebeu, nem de inutilizar o escrow que ele mesmo deveria enviar. |
| A4 | **Processo local comprometido** (mesma máquina, outro usuário ou sem a chave do canal) | Executa código na máquina, sem ser o usuário dono do sidecar | Não consegue usar o canal local (ACL do pipe/socket mais desafio HMAC, ou token portador), nem ler as chaves (cofre do sistema). **Se** o processo roda como o mesmo usuário, ou é o próprio agente comprometido, ele pode pedir envios ao sidecar em nome do agente; ainda assim não extrai as chaves privadas pela interface do sidecar. |
| A5 | **Organização maliciosa** (no modo com escrow) | Controla a âncora, a semente mestra e a chave de escrow | No modo padrão (E2E) a organização não lê nada. Com escrow ligado, ela lê as mensagens entre membros da própria organização: é o objetivo do escrow. Ela **não** lê mensagens com outras organizações nem de agentes sem atestação dela. Ela pode atestar um agente falso com o próprio nome da organização, mas não pode forjar um `agent_id` existente: o identificador é derivado da chave do agente, e a KEL é fixada pelos pares. |

## Propriedades

1. **Sigilo:** só o destinatário (e, com escrow ligado e entre membros da mesma organização, a organização) decifra o conteúdo.
2. **Autenticidade:** o receptor sabe qual `agent_id` enviou cada mensagem.
3. **Integridade:** alteração de qualquer byte autenticado é detectada.
4. **Não repetição:** cada envelope é aceito no máximo uma vez, mesmo após reinício; cada mensagem de sessão também.
5. **Sigilo progressivo nas sessões:** chaves de mensagem apagadas após o uso; comprometimento futuro das chaves de longo prazo não revela mensagens de sessão passadas. Envelopes de um tiro **não** têm sigilo progressivo contra o comprometimento da chave de acordo do destinatário (mitigado pela rotação).
6. **Recuperação após comprometimento** nas sessões, pelo passo DH do ratchet.
7. **Falha fechada** em Card, KEL ou lista de revogação vencidos ou inválidos.

## Fora do escopo

* **Análise de tráfego:** IPs, horários, tamanhos e frequência continuam observáveis.
* **Comprometimento do sistema operacional** ou do usuário dono do sidecar: quem controla a conta lê o cofre de chaves.
* **Computadores quânticos:** a suíte usa X25519 e Ed25519.
* **Negação de serviço:** não há limitação de taxa nem garantias de disponibilidade.
* **Conteúdo malicioso** de um par autenticado (injeção de prompt, dados falsos): é tema do pacote opcional que usa o gancho de política.
* **Canais laterais** de tempo da implementação em Python.

## Riscos residuais conhecidos

* O IK permite repetir a mensagem 1 do handshake (custo de recursos no respondedor, sem acesso à sessão).
* O escrow não é verificável pelo receptor (seção 11 da especificação).
* A primeira busca do Card de um agente sem organização confia na URL usada (TOFU); depois disso, a KEL fica fixada.
* A implementação não teve auditoria independente. O modelo formal do handshake está em `docs/formal/` (ticket #11), mas ainda não foi verificado por ferramenta (ver `docs/formal/README.md`).
