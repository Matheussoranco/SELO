# Cripto Agent

## Breve descrição

Cripto Agent é uma prova de conceito de comunicação autenticada e criptografada
entre agentes de uma organização. Destina-se a desenvolvedores de agentes e equipes
de infraestrutura que precisam integrar serviços em diferentes máquinas e contas.
Oferece descoberta de capacidades autorizadas, chamadas de ferramentas e habilidades
e rejeição de mensagens repetidas. A implementação atual é experimental e síncrona.

## Visão de projeto

### Cenário positivo 1

Uma desenvolvedora configura um agente de atendimento para consultar as capacidades
do agente de apoio. O administrador já cadastrou os certificados e autorizou a
ferramenta de eco. O primeiro agente envia um texto, o segundo autentica a origem,
executa a operação e devolve o resultado pela conexão criptografada. O exemplo
executável representa esse fluxo sem usar dados reais de clientes.

### Cenário positivo 2

Um integrador precisa delegar análise de texto a outro serviço. Ele consulta o
catálogo e chama a skill `text.stats`. O serviço devolve contagem de palavras e
caracteres. A identidade não depende do usuário conectado no computador; depende
dos certificados e do cadastro administrado. A execução entre hosts distintos é
um cenário de implantação previsto, ainda pendente de validação física.

### Cenário negativo 1

Um agente recebe certificado válido da organização, mas não foi cadastrado no
destinatário. Sua chamada é rejeitada. O desenvolvedor solicita o cadastro ao
administrador, que decide se deve conceder acesso e a quais capacidades. Emitir
um certificado não equivale a autorizar todas as ferramentas.

### Cenário negativo 2

O chamador perde a conexão após enviar uma ação. Ao reenviar o mesmo UUID, recebe
erro de repetição. O protótipo não mantém resultados consultáveis e não consegue
informar se a primeira execução terminou. O integrador precisa reconciliar o estado
antes de tentar uma operação com efeitos novamente. Esse limite orienta a evolução
para tarefas persistentes e idempotência de negócio.

## Documentação técnica

Requisitos funcionais: autenticar pares; consultar catálogo; chamar capacidades;
validar organização e destinatário; negar acesso por padrão; detectar repetição.
Requisitos não funcionais: TLS 1.3, corpo limitado a 64 KiB, validade curta e
persistência dos identificadores. Não há compromisso de disponibilidade ou vazão.

Arquitetura: cada processo contém cliente HTTPS, servidor mTLS, registro de
capacidades, política de autorização e SQLite de repetição. Configuração contém
diretório de endpoints e associação entre fingerprints e IDs. A mesma biblioteca
pode ser incorporada a runtimes de agentes independentes do modelo de linguagem.

O código é Python 3.11+, com biblioteca padrão no runtime. `cryptography` é usado
apenas para emitir certificados descartáveis dos testes e da demonstração.
O contrato de dados e os limites de segurança estão em `protocolo.md`.

## Manual de utilização

Para desenvolvedores: seguir os comandos do README para preparar o ambiente,
iniciar o destinatário, consultar o catálogo e chamar tool/skill. Para adicionar
uma capacidade, registrar um handler com validação de argumentos e conceder a
permissão específica. Reexecutar os testes após alterar o contrato.

Para administradores: emitir identidades individuais, configurar o diretório,
definir permissões e proteger chaves com ACLs. Para rede entre hosts, emitir SANs
corretos e configurar endereço de escuta e regras de rede conforme o README.

Se houver falha de certificado, verificar validade, CA, SAN, relógio e fingerprint;
não desativar TLS. Se houver `forbidden`, conferir a tripla de permissão. Se houver
`replay`, não forçar uma nova tentativa de efeito sem reconciliar seu resultado.
Se houver timeout, verificar conectividade e duração do handler; timeout não
garante cancelamento. Certificados de demonstração vencidos devem ser gerados em
uma pasta nova e usados por ambos os agentes de teste.

## Validação e evolução

A suíte automatizada usa conexões HTTPS locais, certificados gerados por teste,
casos positivos e rejeições de identidade, permissão, validade e repetição.
Isso não comprova operação em uma organização real. Homologação entre máquinas,
integração com runtimes de agentes, adaptadores A2A/MCP, gestão de certificados,
auditoria, isolamento e tarefas assíncronas permanecem como trabalho futuro.

Este texto organiza a documentação segundo as seções do modelo de relatório
fornecido. Os cenários descrevem intenção e limites, sem inventar usuários ou
experimentos de campo realizados.
