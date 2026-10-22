# SELO -- imagem minima para revisores: `docker build -t selo . && docker run --rm selo`
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY cripto_agent ./cripto_agent
COPY experiments ./experiments
COPY tests ./tests
RUN pip install --no-cache-dir .
CMD ["python", "-m", "cripto_agent", "demo"]
