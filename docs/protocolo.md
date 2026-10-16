# Protocolo organizacional versão 1

## Transporte e confiança

Cada endpoint exige HTTPS com TLS >= 1.3, certificado cliente validado pela CA e
certificado cliente cadastrado por fingerprint. O cliente valida CA, hostname e
fingerprint do servidor. Não há fallback HTTP, redirecionamento ou confiança em
`sender` sem confrontá-lo com a identidade autenticada.

Identidades pertencem ao diretório administrado; um certificado assinado pela CA
não recebe acesso automaticamente. O campo `organization` deve coincidir com a
organização do servidor, assim como `recipient` com seu ID. O cadastro de um par
declara administrativamente a associação entre certificado, agente e organização.

## Descoberta e invocação

`GET /v1/capabilities` retorna version, organization, agent e capabilities. Cada
capacidade contém kind, name e description. Apenas capacidades autorizadas ao
chamador aparecem. A consulta exige autenticação.

`POST /v1/messages` exige `Content-Type: application/json` e `Content-Length`
único; transferência chunked não é suportada. Limite de corpo e resposta: 65536
bytes. Todos os campos abaixo são obrigatórios e campos extras são rejeitados:

```json
{
  "version": "1",
  "id": "b2cb00ac-4b4f-4db5-8ac6-71b29adbc634",
  "organization": "demo-org",
  "sender": "agent-a",
  "recipient": "agent-b",
  "issued_at": 1792152000,
  "expires_at": 1792152060,
  "kind": "tool",
  "name": "echo",
  "arguments": {"text": "Ola"}
}
```

Os tempos são segundos Unix UTC; os números do exemplo são ilustrativos e devem
ser substituídos pelo relógio atual. `issued_at` deve estar entre agora menos 120s
e agora mais 30s. `expires_at` deve ser futuro e não ultrapassar issued_at + 120s.
O cliente padrão usa validade de 60s. UUID identifica uma tentativa, não uma operação
de negócio durável. `kind` é `tool` ou `skill`, conforme o registro local.

Sucesso HTTP 200: `{"version":"1","id":"UUID","sender":"agent-b","result":{...}}`.
Erros: `{"error":"codigo"}`. 400 indica envelope, versão, argumentos ou validade
inválidos; 403 indica identidade/permissão; 404 rota inexistente; 409 repetição;
413 corpo excessivo; 415 tipo de conteúdo; 500 falha interna/resultado excessivo.
Falhas TLS ocorrem antes de uma resposta HTTP.

## Entrega e repetição

O par `(sender, id)` é reservado em SQLite antes do handler. Repetições são rejeitadas
enquanto a mensagem seria válida, inclusive após reiniciar usando o mesmo banco.
Registros vencidos são removidos na próxima chamada válida. O banco não armazena
payloads ou resultados. Não apagar/recriar o banco durante a janela de validade.

Uma falha pode acontecer após executar a ação e antes de entregar sua resposta.
Não repetir automaticamente com um UUID novo, pois isso pode duplicar efeitos.
Operações financeiras ou outros efeitos relevantes exigem idempotência de negócio
e consulta de estado adicionais. As capacidades de demonstração não têm efeitos.

## Modelo de ameaça e limites

Escuta e adulteração na rede são tratadas pelo TLS; falsificação de remetente pelo
vínculo com certificado; capacidades indevidas pela política local; reenvio pelo
registro persistente. Os endpoints e seus administradores são confiáveis. Um host
comprometido pode ler mensagens e usar sua chave. O protocolo não evita prompt
injection, abuso de uma capacidade já autorizada ou esgotamento de recursos.

Chaves, políticas e diretório nunca são recebidos por uma chamada de agente.
Rotação exige atualizar certificados e fingerprints de forma coordenada e reiniciar
os processos. Remover o fingerprint e reiniciar bloqueia esse par; não há OCSP/CRL
automáticos. Logs de sucesso usam metadados e não argumentos; não há trilha de
auditoria completa nem armazenamento imutável.

## Evolução da interoperabilidade

A2A fornece um contrato padronizado de comunicação entre agentes; MCP fornece
um contrato para acesso a ferramentas. Um adaptador futuro deverá traduzir contratos
e preservar a identidade autenticada, sem transformar descrições de skills em
permissões. É necessário fixar versões, especificar erros/cancelamento e testar
conformidade antes de anunciar compatibilidade com esses padrões.
