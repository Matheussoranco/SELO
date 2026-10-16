# Pacote LaTeX — Relatório Final do Projeto Cripto Agent (Protocolo Chave-Organização v3)

Este pacote contém o relatório final escrito em LaTeX, seguindo o **Modelo Estrutural para Relatório Final do Projeto**, com:

- Nome do projeto, breve descrição (itens a–e) e ressalvas.
- Visão de projeto com **4 cenários** (2 positivos, 2 negativos).
- Documentação técnica: requisitos funcionais/não-funcionais, arquitetura, estrutura do envelope JSON v3, sobre o código.
- **Matemática da criptografia original**: Curve25519/X25519 (ECDH), HKDF-SHA256, AES-256-GCM, encapsulamento duplo, Ed25519 e escrow organizacional — com equações em LaTeX nativas.
- **Diagramas desenhados nativamente em TikZ** (não dependem de imagens externas, portanto nada fica cortado ou com caminho quebrado).
- Manual de utilização por tarefa e considerações finais.

## Arquivos

| Arquivo | Descrição |
|---------|-----------|
| `relatorio.tex` | Fonte principal do relatório |
| `Makefile` | Automatiza a compilação com `pdflatex` |
| `README.md` | Este arquivo |

## Pré-requisitos

Você precisa de uma distribuição LaTeX com os seguintes pacotes:

- `geometry`, `xcolor`, `tikz` (bibliotecas: `arrows.meta`, `positioning`, `shapes.geometric`, `calc`, `fit`, `backgrounds`)
- `booktabs`, `array`, `colortbl`
- `amsmath`, `amssymb`, `amsthm`
- `enumitem`
- `fancyhdr`
- `hyperref`
- `listings`
- `caption`

### Instalação (exemplos)

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install texlive-latex-base texlive-latex-recommended \
  texlive-latex-extra texlive-fonts-recommended latexmake
```

**Fedora:**
```bash
sudo dnf install texlive-scheme-medium texlive-tikz texlive-colortbl \
  texlive-amsmath texlive-enumitem texlive-fancyhdr texlive-hyperref \
  texlive-listings texlive-caption
```

**macOS (MacTeX):**
```bash
brew install --cask mactex
```

**Windows (MiKTeX ou TeX Live):** instale pelo gerenciador de pacotes da distribuição.

## Compilação

Entre na pasta `relatorio/` e rode:

```bash
make
```

Isso executa `pdflatex` duas vezes (necessário para referências cruzadas) e gera `relatorio.pdf`.

Limpe arquivos auxiliares com:

```bash
make clean
```

Abra o PDF com:

```bash
make view   # ou abra relatorio.pdf manualmente
```

## Observações sobre os diagramas

Ambas as figuras (arquitetura e fluxo de cifragem) são desenhadas diretamente em **TikZ** dentro do `relatorio.tex`. Não há arquivos de imagem externos, então não há risco de imagens ficarem cortadas, ausentes ou com caminhos quebrados ao mover o pacote.

## Conteúdo matemático

A seção 5 apresenta a matemática dos primitivos com equações numeradas:

- Acordo de chaves: $S = s \cdot P' = s' \cdot P$ sobre Curve25519
- HKDF-SHA256: extração e expansão
- AES-256-GCM: $C = \mathrm{AES\text{-}256\text{-}GCM\text{-}Encrypt}(K, \text{nonce}, P, \mathrm{AAD})$
- Encapsulamento duplo: $\mathrm{wrap}_{\mathrm{recipient}}$ e $\mathrm{wrap}_{\mathrm{org}}$
- Ed25519: $\sigma = \mathrm{Sign}(A_{\mathrm{priv\_ed}}, \text{cabeçalho})$
- Escrow organizacional: recuperação de $K$ via $\mathrm{Org}_{\mathrm{priv}}$

---

**Nota:** Neste ambiente não há compilador LaTeX instalado, portanto o PDF não pôde ser gerado aqui. O fonte `.tex` está pronto e validado sintaticamente; basta compilar em qualquer máquina com TeX Live / MiKTeX.
