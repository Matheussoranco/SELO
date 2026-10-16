# Relatorio Final - Cripto Agent (protocolo SELO)
#
# Requisitos:
#   - TeX Live (pdflatex) ou MiKTeX
#   - Pacotes: geometry, xcolor, tikz, booktabs, array, colortbl, amsmath,
#            amssymb, amsthm, enumitem, fancyhdr, hyperref, listings, caption
#
# Uso:
#   make             # compila o relatorio.pdf (duas passagens para referências)
#   make clean       # remove arquivos auxiliares

TEX := relatorio
PDF := $(TEX).pdf

.PHONY: all clean view

all: $(PDF)

$(PDF): $(TEX).tex
	pdflatex -interaction=nonstopmode -jobname=$(TEX) $(TEX).tex > /dev/null 2>&1 || true
	pdflatex -interaction=nonstopmode -jobname=$(TEX) $(TEX).tex

clean:
	rm -f *.aux *.log *.out *.toc *.nav *.snm *.vrb $(PDF)

view: $(PDF)
	@which xdg-open > /dev/null 2>&1 && xdg-open $(PDF) || \
	 (which open > /dev/null 2>&1 && open $(PDF) || echo "Abra manualmente: $(PDF)")
