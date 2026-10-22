#!/usr/bin/env sh
# Demo do SELO: cria o ambiente virtual na primeira vez e roda os cenarios narrados.
# Uso: ./demo.sh [--lang en]
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo "Criando ambiente virtual e instalando dependencias..."
    python3 -m venv .venv
    .venv/bin/python -m pip install -q -e .
fi
exec .venv/bin/python -m cripto_agent demo "$@"
