# SELO

> **Em transição para o SELO v1.** O SELO v1 é uma extensão do A2A com criptografia de ponta a ponta nativa, desenvolvida no pacote `selo/` (spec: issue #1). O texto abaixo descreve o **protótipo v0**, que agora vive em `selo_v0/` e será a base do pacote opcional de defesa contra injeção de prompt. Os protocolos antigos (`legado/`) foram removidos; o histórico git os preserva.

Prova de conceito em Python para chamadas entre agentes, tools e skills: envelopes cifrados e assinados, tokens atenuáveis, manifestos admitidos pela organização e controle de integridade por rótulos de proveniência. **Não é produto pronto para produção nem uma solução geral contra injeção de prompt.** O núcleo não executa um LLM: o integrador fornece o harness e os handlers.

## Instalação

Execute na raiz deste projeto. Requer Python **3.11+** e `pip`; a dependência de execução declarada em `pyproject.toml` é `cryptography>=46,<47`. O build usa `setuptools>=77`. Não há lockfile garantindo reprodução exata de todas as versões.

Windows (PowerShell, sem necessidade de ativar o ambiente):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m selo_v0 demo
```

Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m selo_v0 demo
```

Nos comandos seguintes, `python` deve ser o interpretador desse ambiente. A instalação pode baixar pacotes do índice configurado no pip. A demo usa objetos locais e dados simulados; não requer chave de API nem serviço de LLM. `demo.bat` e `demo.sh` também automatizam a preparação e a demonstração.

## Uso e testes

```sh
python -m selo_v0 demo --lang pt
python -m selo_v0 bench
python -m unittest discover -s tests -t .
python -m unittest discover -s tests/v0 -t .
python experiments/tap_lab.py
python -m selo_v0 lint --mcp python tests/v0/fake_mcp_server.py
```

- `bench` mede custos locais; não representa latência em produção.
- Os testes usam `unittest` da biblioteca padrão (não exigem pytest), sockets locais, arquivos temporários e subprocessos. O laboratório `tap_lab.py` simula três nós em loopback; não é uma implantação distribuída pronta.
- O servidor MCP de teste contém descrições maliciosas intencionais: o linter pode terminar com código 1 por achados de severidade `error`. Isso não é falha de instalação. `lint --json ARQUIVO` lê uma lista de manifestos sem iniciar MCP.
- **`lint --mcp` executa o comando indicado antes de examinar as descrições.** Não use um servidor desconhecido como se o linter fosse uma sandbox. O subprocesso herda, por padrão, ambiente e permissões do usuário e pode acessar arquivos ou rede.

Após as correções da revisão de 08/11/2026, `python -B -m unittest discover -s tests -q` executou **127 testes, todos aprovados, em 46,159 s**, com Python 3.13.5 no Windows. A suíte emitiu avisos `ResourceWarning` de conexões SQLite não fechadas em testes existentes. A demonstração em português também foi executada com sucesso. Isso valida os casos exercitados, não todas as entradas adversariais nem as garantias de segurança em produção. Não foram reexecutados benchmarks, AgentDojo, Docker ou implantação entre máquinas nesta revisão.

## Componentes e integração

- `selo_v0/envelope.py`, `keys.py`: X25519, HKDF-SHA256, ChaCha20-Poly1305 e Ed25519; hierarquia de chaves por época. Construção própria inspirada em HPKE, **não uma implementação interoperável da RFC 9180**.
- `agent.py`, `tokens.py`: chamadas, anti-replay SQLite e caveats de autorização.
- `manifest.py`, `lint.py`, `mcp_bridge.py`: admissão de manifestos, Merkle, fixação por hash, heurísticas e ponte MCP stdio mínima.
- `provenance.py`: sessões, carimbos e endossos. `org.py` e `audit.py`: autoridade e auditoria sobre envelopes capturados.
- `sandbox.py`: `World().standard()` cria uma organização, agentes e principais de laboratório. **O nome não significa isolamento de processos.**

O integrador deve registrar handlers locais, provisionar certificados e sementes por canal autenticado externo ao serviço HTTP, revisar/admitir manifestos e configurar transporte. Não há comando CLI de implantação de servidores: `serve_org`, `serve_agent`, `OrgClient` e `http_send` são APIs Python.

### Política e revisão humana

1. Revise o código real da tool, seus destinos de rede, efeitos e acesso a dados, além da descrição. As annotations MCP são sugestões não confiáveis. `mcp_bridge.default_gate` é heurístico, e `Organization.admit_manifest(..., approved=True)` não comprova revisão humana. A assinatura cobre o manifesto, não o binário nem o comportamento do handler.
2. Use `ManifestStore.approve(hash)` para fixar a versão revisada. `Agent.learn` verifica mudança apenas se já houver pin; `Agent.call` não verifica o pin automaticamente. Inclua caveat `manifest` no token: `Agent.mint` exige `holder` por padrão, mas **não adiciona expiração, hash ou limite de usos**. A função de baixo nível `tokens.mint` permite tokens sem caveats.
3. O harness deve registrar todo conteúdo relevante e manter seus carimbos. `scope="full"` cita os carimbos já registrados, não descobre contexto omitido. `scope="args"` usa correspondência textual, não rastreamento semântico. Inclua explicitamente `UNKNOWN_SOURCE` na política quando fontes desconhecidas devam bloquear: esse rótulo não implica rejeição automática.
4. Em um bloqueio, apresente ao humano o conteúdo, a origem, a ação e os rótulos que serão removidos. Após revisão, uma interface confiável pode chamar `Principal.endorse(stamp, remove, session, cap=..., ttl=...)` e registrar com `session.endorse(...)`. O código verifica assinatura, papel `endorser`, hash, sessão e validade; **não verifica presença humana ou consentimento**. `cap=""` (padrão) permite qualquer capacidade naquela sessão: escolha capacidade explícita e validade curta.
5. Não contorne bloqueios simplesmente trocando o identificador de sessão. Uma tarefa realmente nova deve ter contexto independente; transportar dados contaminados para uma sessão sem carimbos invalida a proteção. Mantenha chaves, tokens e a interface de aprovação fora do controle do LLM.

## Comunicação de rede e dados expostos

`serve_org` e `serve_agent` usam **HTTP por padrão**, em `127.0.0.1`, porta `0` (escolhida pelo sistema). TLS só é habilitado ao fornecer `ssl_context`; certificados, nomes e confiança TLS devem ser configurados pelo operador.

| Serviço | Rotas |
| --- | --- |
| Agente | `POST /selo/v1/inbox`, `GET /selo/v1/catalog` |
| Organização | `GET /org/v1/params`, `/org/v1/entry?id=...&epoch=...`, `/org/v1/manifest?h=...`, `/org/v1/sth`, `/org/v1/revoked` |

O cliente usa a URL da entrada de época assinada (`org.urls`) para enviar envelopes; não há allowlist de destinos no transporte. Os endpoints GET são públicos: catálogos, esquemas e descrições **não devem conter segredos**. `OrgClient.bootstrap_params` apenas obtém os parâmetros: conferir a chave da organização fora de banda é responsabilidade do operador.

O corpo (capacidade, argumentos, token e contexto) é cifrado, assim como a resposta. Sem TLS, cabeçalho, identidades, época, horários e certificado ficam visíveis. TLS esconde o conteúdo HTTP de observadores passivos, **não os IPs, padrões de tráfego, tempos e tamanhos aproximados**, nem os dados nos endpoints/terminadores TLS. Remetente, destinatário e organização podem ter acesso ao texto; o protocolo não impede cópias ou vazamento por esses participantes.

A ponte MCP usa JSON-RPC por stdin/stdout local; o processo MCP e os handlers podem fazer suas próprias conexões, fora da proteção do envelope. O adaptador AgentDojo conecta a API compatível com OpenAI em `http://localhost:PORT/v1` para vLLM. Notebooks Colab e dependências/modelos adicionais envolvem downloads e execução em infraestrutura de terceiros, consumo de GPU e possíveis custos. Não envie dados reais ou segredos sem revisar esses fluxos. AgentDojo/vLLM não são dependências do núcleo.

## Limitações de segurança

- **Organização confiável:** a semente mestra permite derivar chaves de leitura das épocas. Isso é escrow deliberado, não sigilo ponta a ponta contra a organização. A chave mestra sozinha não permite assinar com a chave privada original do agente; porém a autoridade certificadora pode emitir outro certificado para o mesmo ID, com chave que controla. Não há proteção geral contra personificação pela CA.
- **Shamir não impõe quórum operacional:** `master_shares` divide o segredo sem apagar `Organization._master`; `Organization.open` não exige partes nem autentica o nome do auditor. Não há integração HSM nem zeragem segura da memória Python. A catraca descarta referências antigas e retém normalmente épocas atual/anterior; a semente atual deriva épocas futuras. Não há sigilo progressivo contra a organização ou recuperação automática após comprometimento.
- **Defesa contra injeção condicional:** rótulos, manifestos, políticas, harness e UI devem estar corretos. Assinaturas não provam que o conteúdo é verdadeiro ou benigno. O protocolo não impede canais ocultos, ferramentas maliciosas admitidas ou uso direto das tools fora do SELO.
- **Anti-replay e usos:** SQLite é `:memory:` por padrão. Persistência requer `Agent(db=...)`; não há execução exatamente uma vez nem transação envolvendo efeito externo. `max_uses` usa uma reserva atômica no SQLite antes do handler, persistente quando `db` aponta para arquivo. Tentativas autorizadas consomem uso mesmo se o handler falhar, pois efeitos externos podem já ter ocorrido. A tabela é criada automaticamente em bancos existentes; contadores antigos em memória não podem ser recuperados. Preserve o banco e as chaves no reinício. `Agent.token_uses()` consulta as reservas; não apague contadores de tokens ainda válidos.
- **Revogação:** `org.revoke` altera o conjunto local e impede novas entradas para o certificado registrado revogado. Clientes remotos precisam buscar/aplicar a lista assinada. Não há atualização automática, controle de frescor da lista ou prazo universal de revogação de uma época; entradas/cache podem continuar utilizáveis e a semente antiga deriva chaves futuras.
- **Validação parcial:** `validate_args` implementa apenas parte de JSON Schema; palavras-chave desconhecidas são ignoradas e `oneOf` é tratado como alternativas sem exigir exclusividade. Não equivale a um validador completo. O JSON canônico aceita floats finitos e usa a serialização Python, não RFC 8785.
- **Limites distintos:** `seal` limita o corpo a 128 KiB; `open_envelope` limita o ciphertext decodificado a 256 KiB; o POST HTTP limita o corpo recebido a 256 KiB + 4096 bytes. Não são uma garantia única de tamanho de envelope. O experimento AgentDojo eleva limites em memória.
- **Disponibilidade e durabilidade:** servidor HTTP de referência sem rate limiting ou isolamento de handlers; estado organizacional, pins e logs são principalmente em memória. Não há provas de consistência de Merkle entre observadores, segurança pós-quântica ou auditoria criptográfica independente documentada.

## Auditoria humana e evidências

A aplicação deve capturar e guardar os envelopes de **requisições e respostas em ordem**, com controle de acesso e retenção definida. O transporte não fornece um coletor persistente automático. A organização pode executar:

```python
from selo_v0.audit import audit_traffic
resultado = audit_traffic(org, envelopes, auditor="identificacao-do-revisor", reason="motivo autorizado")
```

`org` e `envelopes` são objetos previamente provisionados/capturados, não um serviço remoto de auditoria. `Organization.open` autentica/decifra e registra leituras bem-sucedidas, exigindo strings não vazias de auditor e motivo. Isso **não autentica o auditor nem obriga todas as leituras possíveis a passar pelo log**: quem possui a semente pode derivar a chave diretamente.

`AuditLog.records` é uma lista em memória encadeada por hashes; `verify()` verifica sua consistência interna. Sem checkpoint externo confiável, truncamento ou reescrita integral não são impedidos. A revisão humana deve autorizar o acesso, proteger custodiantes/chaves, exportar evidências e checkpoints para armazenamento independente e conferir achados e integridade da captura. Esses controles são responsabilidades externas, não recursos prontos do protótipo.

`audit_traffic` detecta certas omissões apenas em chamadas `full`, na mesma sessão, com resultados anteriores presentes na captura, e verifica propagação de rótulos de pares chamada/resposta encontrados. Captura incompleta, troca de sessão ou modo `args` deixam lacunas. Revogações atuais podem impedir abertura histórica. Um retorno sem achados não comprova ausência de abuso; achados não desfazem ações executadas.

## Relatórios e resultados existentes

- `relatorio/Relatorio_Final_Cripto_Agent.docx`: relatório Word, editado preservando o pacote e a estrutura de formatação.
- `relatorio/relatorio.tex`: versão LaTeX; `relatorio/Makefile` usa `pdflatex` em duas passagens. Word e LaTeX são documentos separados, sem sincronização automática.
- `results/protocol_attacks.json`: registro de 36 cenários (34 bloqueados e 2 detectados por auditoria), não avaliação exaustiva de segurança.
- `results/groundtruth.json`: replay sem LLM de 97 tarefas: 44 sucessos em `full`, 49 em `args`, 97 com endossador ideal simulado (173/156 endossos). **Não mede eficácia com humanos reais ou taxa de sucesso de ataques contra LLMs.**
- `results/overhead.json`: medições históricas de desempenho com identificação de ambiente. Não foram reproduzidas nesta revisão.

Experimentos podem gravar em `results/` e sobrescrever resultados; escolha outro `--out` quando disponível. Resultados com LLMs reais, homologação entre máquinas, renderização visual final dos documentos e controles de produção permanecem pendentes. Veja também `relatorio/REVISAO.md` para o registro desta revisão.

## Licença

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

Copyright (c) 2025-2026 Matheus Soranço. Licenciado sob a **Creative Commons Atribuição-NãoComercial-CompartilhaIgual 4.0 Internacional** (SPDX: `CC-BY-NC-SA-4.0`); o texto legal está em `LICENSE`.

Em resumo (o texto legal prevalece): você pode copiar, adaptar e redistribuir, com atribuição, apenas para fins não comerciais, e adaptações devem usar a mesma licença. A licença não concede direitos de patente nem de marca. O GitHub exibe "NOASSERTION" porque seu detector não reconhece licenças Creative Commons NonCommercial.
