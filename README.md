# Cripto Agent

Prova de conceito de um protocolo de comunicação entre agentes de uma organização,
independentes de máquina, usuário do sistema operacional ou fornecedor de modelo.
O protocolo transporta JSON por HTTPS com TLS 1.3 e certificados em ambas as pontas
(mTLS). Cada agente pode atuar como cliente e servidor.

## O que está implementado

- Identidade por certificado emitido por uma CA confiável e impressão digital SHA256
  cadastrada pelo administrador. O cliente também verifica hostname e certificado
  específico do destinatário antes de enviar a mensagem.
- Diretório estático de agentes e catálogo de capacidades filtrado por permissão.
- Invocação de tools e skills com lista explícita de permissões por remetente.
- Envelope versionado, destinatário, organização, UUID e prazo de validade.
- Rejeição persistente de mensagens repetidas usando SQLite.
- Duas capacidades de demonstração: `tool/echo` e `skill/text.stats`.
- Cliente, servidor, gerador de certificados de desenvolvimento e testes HTTPS.

Uma tool é uma operação concreta; uma skill é uma capacidade de nível mais alto
implementada localmente, que pode compor operações. Nesta demonstração a skill
calcula estatísticas de texto. Skills não são arquivos de instruções baixados e
executados remotamente. Nenhuma mensagem instala código ou concede permissões.

## Executar no Windows

Python 3.11 ou posterior, com OpenSSL que suporte TLS 1.3.

```powershell
cd C:\Users\mathe\Documents\Code\cripto_agent
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python scripts/dev_pki.py
.\.venv\Scripts\python -m unittest discover -s tests -v
```

O gerador recusa sobrescrever uma pasta existente. Os certificados de demonstração
duram sete dias, valem apenas para localhost/127.0.0.1 e as chaves privadas de teste
ficam sem senha em `.local/pki`. Não compartilhar essa pasta nem usar essas chaves
em implantação real. A chave da CA de teste não é gravada.

Em um terminal, iniciar B:

```powershell
.\.venv\Scripts\python -m cripto_agent serve --config .local/pki/agent-b.json
```

Em outro terminal, A descobre e chama B:

```powershell
.\.venv\Scripts\python -m cripto_agent catalog --config .local/pki/agent-a.json
.\.venv\Scripts\python -m cripto_agent call --config .local/pki/agent-a.json --text "Mensagem entre agentes"
.\.venv\Scripts\python -m cripto_agent call --config .local/pki/agent-a.json --kind skill --name text.stats --text "Mensagem entre agentes"
```

Para testar o sentido inverso, iniciar também A com `serve` e usar a configuração
de B nas chamadas com `--recipient agent-a`. Encerrar servidores com Ctrl+C.

## Usar entre máquinas e perfis

1. A equipe administradora emite certificados individuais com DNS/IP real em SAN,
   usos de cliente/servidor e cadeia de confiança da organização. Cada host recebe
   somente sua chave privada, seu certificado e a CA pública.
2. Configurar `agent_id` e `organization`, caminhos `ca`, `cert`, `key` e `database`.
   Caminhos relativos são resolvidos em relação ao arquivo de configuração.
3. Cadastrar em `peers` o hash SHA256 do certificado DER de cada par autorizado,
   associado ao ID do agente. Não é o hash do arquivo PEM.
4. Cadastrar `permissions` como triplas `[remetente, tipo, capacidade]`. Ausência
   de permissão implica negação. Cadastrar URLs HTTPS reais em `directory`.
5. Ajustar `bind` para o IP da interface privada e `port`; permitir essa porta
   apenas nos segmentos aprovados da organização. Não desativar validação TLS.
6. Proteger arquivos de configuração, banco e chaves com ACLs da conta de serviço.
   Sincronizar relógios. Testar primeiro em uma rede de homologação.

Não há vínculo com o perfil Windows: a identidade é o certificado administrado.
Não há descoberta automática de máquinas; o diretório é configurado explicitamente.

## Extensão e limites

Registrar `Capability(kind, name, description, handler)` em `Agent.register` e
adicionar as permissões correspondentes. O handler recebe um objeto JSON e deve
validar argumentos, retornar JSON e implementar suas regras de negócio. Consulte
`cripto_agent/__main__.py` para exemplos. Não executar comandos recebidos como texto.

O protocolo é próprio, versão 1. **Não implementa A2A nem MCP**. A interoperabilidade
atual é entre clientes que implementem este contrato HTTP/JSON, em qualquer linguagem.
Adaptadores A2A para agentes e MCP para ferramentas são uma evolução prevista.

Este é um protótipo síncrono com servidor de referência da biblioteca padrão,
adequado para experimentação, não um serviço pronto para produção. Faltam gestão
centralizada/rotação/revogação de certificados, autorização delegada, isolamento de
handlers, limites de concorrência de produção, rate limiting, auditoria durável,
fila de tarefas e testes entre máquinas reais. Um handler lento bloqueia o servidor;
o timeout de rede não cancela a execução do handler. Não prometer execução exatamente
uma vez: uma falha após reservar o UUID pode deixar resultado desconhecido.

A criptografia protege o transporte direto entre agentes. TLS não protege conteúdo
após descriptografia, arquivos em disco nem intermediários que terminem TLS. Para
filas ou brokers não confiáveis será necessário um perfil adicional de criptografia
de mensagem ponta a ponta. Os certificados e diretório são fronteiras de confiança.

Documentos adicionais: `docs/protocolo.md` e `docs/relatorio-projeto.md`.

Referências primárias consultadas em 16/10/2026:
- A2A: https://a2a-protocol.org/latest/
- MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- TLS no Python: https://docs.python.org/3/library/ssl.html
