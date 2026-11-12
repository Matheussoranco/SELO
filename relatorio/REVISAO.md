# Revisão documental — 08/11/2026

## Escopo e método

Revisão de `Relatorio_Final_Cripto_Agent.docx` e `relatorio.tex` contra a implementação local, com novo `../README.md` em português. A revisão documental foi acompanhada por correções de implementação e regressões descritas abaixo. Não houve escolha de licença ou commits.

Foram inspecionados os módulos principais do SELO, CLI, empacotamento, testes, adaptador AgentDojo e resultados JSON. A revisão é documental e estática, complementada pela suíte existente, não uma auditoria criptográfica independente. Fontes externas e referências bibliográficas não foram revalidadas na internet.

## Alegações corrigidas e base no código

| Alegação anterior | Correção / limitação | Evidência local |
| --- | --- | --- |
| A organização lê, mas não pode personificar agentes | A semente não fornece a chave original de assinatura, mas a CA pode certificar outra chave para o mesmo ID | `org.py:Organization.enroll`, `keys.py:verify_cert`, `envelope.py:open_envelope` |
| Shamir impõe custódia por quórum; toda leitura é auditada | `_master` permanece residente; `open` não pede partes, autentica o envelope mas não o auditor, e registra apenas leituras realizadas por essa API | `org.py:master_shares`, `Organization.open` |
| Log encadeado é uma trilha durável/inviolável | Lista em memória; encadeamento interno não detecta toda reescrita/truncamento sem checkpoint externo confiável | `org.py:AuditLog` |
| Injeção nunca causa ação privilegiada | Guarda opera sobre rótulos citados e proibidos; completude depende do harness, e conteúdo malicioso pode não estar rotulado | `agent.py:_execute`, `provenance.py:effective_taint`, `Session` |
| Manifesto desconhecido implica rejeição automática | Acrescenta `UNKNOWN_SOURCE`, que precisa estar na política proibida | `provenance.py:effective_taint`, `agent.py:_execute` |
| Endosso implica decisão humana e capacidade sempre mínima | API verifica assinatura/papel, não presença humana; `cap=""` é curinga | `provenance.py:verify_endorsement`, `Principal.endorse` |
| Todo token está preso ao hash do manifesto e tem limites | `Agent.mint` exige holder por padrão; hash, prazo e usos são caveats opcionais. Função de baixo nível admite lista vazia | `agent.py:mint`, `tokens.py:mint`, `verify` |
| Pin protege automaticamente toda chamada | `approve` fixa inicialmente; `learn` compara apenas se já fixado; `call` não verifica o pin | `manifest.py:ManifestStore`, `agent.py:learn`, `call` |
| Manifesto assinado prova segurança da tool | Assina descrição/esquema/política, não o código do handler; linter/gate são heurísticos | `manifest.py:publisher_sign`, `agent.py:register`, `mcp_bridge.py:default_gate` |
| Replay persistente e max_uses garantido | SQLite é em memória por padrão. A implementação foi corrigida para reservar usos atomicamente antes do handler; persistência exige db em arquivo e tentativas autorizadas com falha também consomem uso | `agent.py:__init__`, `_reserve`, `_execute` |
| Revogação em no máximo uma época | Requer buscar/aplicar listas remotas, sem atualização automática nem controle de frescor; cache e derivação futura de sementes limitam a garantia | `org.py:revoke`, `epoch_entry`, `transport.py:OrgClient.revoked`, `keys.py:ratchet` |
| JSON sem floats e validação JSON Schema completa | Floats finitos aceitos; serialização Python, não RFC 8785; palavras-chave desconhecidas ignoradas e oneOf sem exclusividade | `util.py:canon`, `manifest.py:_check` |
| TLS oculta todos os metadados | Protege conteúdo HTTP; IPs, tempos e tamanhos aproximados continuam observáveis | `transport.py` e limites do transporte TLS |
| HPKE/prova formal aplicável automaticamente | Construção própria inspirada em DH/HKDF/AEAD, domínios/formatos próprios; argumento informal não é redução formal da implementação | `envelope.py`, `keys.py`, `tokens.py` |
| Apagar sementes em Python garante destruição segura | Remoção de referências, sem zeragem; a semente atual deriva futuras e a organização retém a mestra | `keys.py:EpochKeys.advance_to`, `org.py` |
| Auditoria fecha toda lacuna de omissão | Compara chamadas full na mesma sessão e resultados capturados anteriormente; args, troca de sessão e captura incompleta deixam lacunas | `audit.py:audit_traffic` |
| Trocar de sessão é solução para bloqueio | Só é válido com contexto realmente independente; transferir conteúdo sem seus carimbos contorna a hipótese de segurança | `Session`, `Agent.call`, `audit_traffic` |
| Linter MCP pode examinar executável desconhecido com segurança | Inicia subprocesso antes da análise, sem isolamento, herdando ambiente por padrão | `mcp_bridge.py:McpStdioClient.start`, CLI `_lint`/`main` |

Os caminhos da coluna de evidência são relativos a `../cripto_agent/selo/`, exceto a CLI (`../cripto_agent/__main__.py`).

## Resultados e validação

- **Suíte executada:** `unittest.defaultTestLoader.discover('tests')`, seguida de `TextTestRunner`, equivalente à descoberta de `python -m unittest discover -s tests`.
- **Resultado inicial:** 120 testes aprovados em **46,055 s**. Após as correções de tokens, `python -B -m unittest discover -s tests -q`: **127 testes aprovados em 46,159 s**, Python **3.13.5** no Windows. A suíte completa emite `ResourceWarning` de conexões SQLite não fechadas em testes existentes; o resultado foi OK, não uma execução sem avisos.
- Bytecode desativado (`PYTHONDONTWRITEBYTECODE=1`, `-B`); `tempfile.tempdir` direcionado a uma pasta temporária sob `relatorio/`, removida ao final. Não restaram temporários dessa validação.
- **Resultados históricos conferidos, não reexecutados:** `results/protocol_attacks.json` registra 36 cenários (34 bloqueados e 2 detectados); `results/groundtruth.json` registra 97 tarefas, com 44 sucessos full, 49 args e 97 com endossador ideal simulado (173 e 156 endossos); `results/overhead.json` contém as latências citadas e o ambiente original.
- As contagens antigas de 92/108 testes foram substituídas pelo resultado observado. Não foram inferidas taxas de ataque com LLM a partir de replay sem LLM.
- **LaTeX:** ambientes `begin/end` balanceados; `git diff --check -- relatorio README.md` sem problemas. Uma primeira tentativa do verificador auxiliar falhou por escape de regex no shell; corrigido o comando, a verificação passou. Isso não é compilação LaTeX.

## Preservação do Word

O DOCX foi inspecionado antes de editar (14 membros ZIP, 574 parágrafos, incluindo tabelas e runs com formatação distinta). Não foi recriado com biblioteca de geração de documentos.

Um script auxiliar descartado após uso fez alterações localizadas de texto em **66 parágrafos** e uma atualização posterior das ressalvas sobre tokens, distribuindo diferenças nos runs existentes. Preservou propriedades de parágrafo/run, tabelas, seções e relações; só ajustou `xml:space` quando necessário para preservar espaços dos textos editados.

Validações antes da substituição do arquivo:

1. Mesma lista/ordem de membros ZIP; **somente `word/document.xml` mudou**.
2. Os outros 13 membros, incluindo estilos, imagens, tema, numeração e relações, permaneceram **idênticos byte a byte**.
3. Estrutura XML fora de texto/indicação de espaços preservada; mesma contagem de parágrafos e todos os textos-alvo conferidos.
4. CRC do ZIP e parse de todos os XML/relacionamentos válidos.
5. SHA-256 original e final registrados em `validacao_docx.json`; hash final reconferido após edição.

O registro JSON inclui o hash final após a atualização de tokens. Não é assinatura digital nem substitui custódia independente de evidências.

## Pendências e limites desta entrega

- **Conferência visual no Word/LibreOffice:** estrutura e estilos foram preservados, mas o aumento de texto pode alterar quebras de linha/página e alturas de tabelas. Não foi renderizado para afirmar equivalência visual de paginação.
- **Compilação LaTeX/PDF:** `pdflatex`, Pandoc e LibreOffice não foram encontrados no PATH consultado. Verificação sintática simples não substitui compilação e inspeção de layout.
- **Sem reexecução de Docker, benchmarks, matriz de ataques, laboratório isoladamente ou AgentDojo/LLMs**, nem homologação entre máquinas físicas. Os testes de transporte da suíte usam loopback.
- **Revisão humana de segurança:** políticas de rótulos, revisão de código de tools, decisões de endosso, separação de custodiantes, autorização de auditor e proteção/retenção dos registros ainda são responsabilidades operacionais. Não foram implementados recursos novos de produção.
- **Correções de implementação:** framing HTTP, fechamento de conexões, parâmetros de consultas, timeout e validação MCP; reserva atômica de tokens em SQLite, preservação de caveats fornecidos por gerador, rejeição de caveat malformado e de identificadores com quebra de linha. Laboratório atualizado para `Agent.token_uses()`. Foram adicionadas regressões. O arquivo não rastreado `nul` já aparecia na inspeção inicial e foi preservado.
- **Sem escolha de licença e sem commits.**
