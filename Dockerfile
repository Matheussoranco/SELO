# SELO v1 -- imagem para revisores: roda a suite de testes num Linux limpo.
#   docker build -t selo . && docker run --rm selo
# Validacao em dois hosts (precisa de NET_ADMIN para criar namespaces de rede):
#   docker run --rm --cap-add NET_ADMIN selo python tests/twohost/scenario.py
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY selo ./selo
COPY selo_v0 ./selo_v0
COPY tests ./tests
COPY experiments ./experiments
RUN pip install --no-cache-dir ".[interop]"
# Sem cofre do sistema no conteiner: cofre em arquivo com senha de teste.
ENV SELO_KEY_PASSWORD=senha-de-teste-do-conteiner
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-t", "."]
