# SELO

[![Licença: Apache 2.0](https://img.shields.io/badge/licen%C3%A7a-Apache%202.0-blue)](LICENSE)

SELO é uma extensão do A2A 1.0 para comunicação cifrada de ponta a ponta entre agentes. Cada agente usa um sidecar local. Os sidecars guardam as chaves, verificam a identidade dos pares e transportam mensagens, tarefas, eventos SSE e notificações push.

> **Status:** `1.0.0.dev0`. Protótipo sem auditoria criptográfica independente. Não use para proteger dados reais sem uma revisão de segurança.

```text
Agente Alice → sidecar Alice ══ canal cifrado ══ sidecar Bob → Agente Bob
```

A primeira mensagem para um par usa um envelope HPKE assinado. As próximas podem usar uma sessão Noise IK com Double Ratchet. O Agent Card assinado anuncia a identidade, as capacidades e a extensão SELO. Fora do loopback, os sidecars também exigem TLS. A criptografia não oculta IPs, tamanhos ou horários do tráfego.

O agente fala com o próprio sidecar por named pipe no Windows, socket Unix em sistemas POSIX ou HTTP em loopback com token. Um cliente A2A pode usar a interface HTTP local sem implementar SELO. Na rede entre sidecars, o par precisa entender a extensão: não há fallback para A2A em texto claro. Organizações são opcionais; a federação exige âncoras de confiança explícitas e o escrow auditado é restrito a mensagens entre membros da mesma organização.

## Instalação

Na raiz do repositório, com Python 3.11 ou superior:

```sh
python -m venv .venv
```

Ative o ambiente no terminal que for usar:

```sh
# Bash / zsh
source .venv/bin/activate
```

```powershell
# PowerShell
.\.venv\Scripts\Activate.ps1
```

```sh
python -m pip install -e .
```

`cryptography` é a única dependência direta de execução. O `a2a-sdk` só é necessário para os testes de interoperabilidade.

## Primeira mensagem

Use a mesma pasta de trabalho e o mesmo ambiente virtual em todos os terminais. Deixe os agentes e os sidecars rodando até terminar o teste.

**1. Inicie dois agentes de referência**, um comando por terminal:

```sh
python -m selo.refagent --name alice --port 9101
python -m selo.refagent --name bob --port 9102
```

**2. Gere as configurações** em outro terminal:

```sh
selo init --config alice.json --name alice --agent-url http://127.0.0.1:9101/ --port 8101
selo init --config bob.json --name bob --agent-url http://127.0.0.1:9102/ --port 8102
```

O sidecar usa o cofre do sistema por padrão. Se ele não estiver disponível, acrescente `--keystore file` aos comandos `selo init` e defina `SELO_KEY_PASSWORD` no ambiente de cada sidecar antes de iniciá-lo.

**3. Inicie os sidecars**, um por terminal, e espere a linha `READY` em ambos:

```sh
selo sidecar --config alice.json
selo sidecar --config bob.json
```

**4. Envie uma mensagem** de Alice para Bob pelo canal local do sidecar de Alice:

```sh
selo send --config alice.json --peer http://127.0.0.1:8102 --text "olá, bob"
```

A resposta JSON do agente Bob contém `eco: olá, bob`.

Para conectar máquinas distintas, configure `--host`, `--tls-cert` e `--tls-key` no `selo init`. A URL pública do sidecar precisa corresponder ao certificado; para uma CA privada, configure `tls.ca_file` nos pares. A [especificação](docs/spec/selo-v1.md) descreve o transporte, a interface A2A local e as regras de confiança.

## Testes e limites

```sh
python -m pip install -e ".[interop]"
python -m unittest discover -s tests -t .
```

A suíte inclui o protótipo v0 e os testes do SDK. Sem o extra `interop`, os testes do SDK são pulados. O [relatório de rede](docs/validacao/duas-maquinas.json) registra **19 de 19 verificações** com `cryptography` 46.0.7: comunicação, tarefas, SSE, push, rotação, revogação e rejeição das falhas simuladas. O cenário usou três namespaces de rede no mesmo kernel WSL2. Ele não valida máquinas físicas distintas, internet pública ou travessia de NAT.

A execução do [modelo ProVerif](docs/formal/README.md) terminou por tempo limite sem veredito. Os testes de execução não substituem essa verificação formal. Os cofres DPAPI e em arquivo foram exercitados; Keychain e Secret Service ainda não foram validados.

## Onde ler mais

- [Especificação SELO v1](docs/spec/selo-v1.md): formato das mensagens, sessões, transporte e decisões de projeto.
- [Modelo de ameaça](docs/spec/modelo-de-ameaca.md): adversários, garantias pretendidas e exclusões.
- [Glossário](CONTEXT.md): termos usados no protocolo.
- [SELO v0](docs/selo_v0.md): documentação do protótipo anterior, mantido separado em `selo_v0/`.

## Licença

Copyright (c) 2025–2026 Matheus Soranço. O material original do SELO é licenciado sob a [Apache License 2.0](LICENSE) (`Apache-2.0`). Os vetores de teste de terceiros mantêm suas atribuições e os termos de suas fontes, indicadas nos arquivos em [`tests/vectors/`](tests/vectors/).
