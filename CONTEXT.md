# Glossário do SELO

Termos usados no código, nas issues e na especificação (`docs/spec/selo-v1.md`). Use estes nomes; não invente sinônimos.

| Termo | Definição |
| --- | --- |
| **Agente** | Programa A2A que conversa com outros. Não vê chaves privadas. |
| **Sidecar** | Processo `selo sidecar`, um por agente. Guarda chaves, publica o Agent Card, cifra, verifica e entrega. |
| **Canal local** | Ligação agente ↔ sidecar: named pipe / socket Unix com chave de desafio, ou HTTP em loopback com token. |
| **Par** | O outro agente (e seu sidecar) numa conversa. |
| **`agent_id`** | Identificador `selo:...`, derivado da chave de identidade de gênese. Não muda com a rotação. |
| **KEL** | Cadeia de eventos de chave: `inception`, `rotation`, `revocation`. Define as chaves atuais de um `agent_id`. |
| **Fixação** | Registro local do maior `seq` da KEL visto para um par; KEL que não estende a fixada é bifurcação. |
| **Agent Card** | Card A2A 1.0 assinado (JWS EdDSA) com a extensão SELO nos `params`. |
| **Envelope** | Mensagem de um tiro: HPKE para a chave de acordo do destinatário + assinatura Ed25519 do remetente. |
| **Sessão** | Canal contínuo: handshake Noise IK seguido de Double Ratchet. Identificada por `sid`. |
| **Recuo** | Volta ao envelope quando a sessão se perde (`unknown_session`). |
| **Organização** | Âncora Ed25519 opcional que atesta agentes, publica revogações e pode ter escrow. |
| **Âncora confiável** | Organização configurada explicitamente em `trust.orgs`. |
| **Atestação** | Documento da organização que diz "este `agent_id` é meu membro". |
| **Federação** | Confiança entre organizações diferentes, só por âncoras configuradas nos dois lados. |
| **Escrow** | Modo opcional em que a organização lê mensagens entre os próprios membros, com leitura auditada. |
| **Gancho de política** | Chamável configurado que pode recusar requisições e respostas. |
| **Push** | Notificação A2A de mudança de tarefa, entregue como envelope `push` a um destino permitido. |
| **selo_v0** | Protótipo anterior (proveniência, manifestos, linter MCP); base do futuro pacote opcional. |
