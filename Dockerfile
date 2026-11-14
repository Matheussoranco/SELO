# SELO -- imagem minima para revisores: `docker build -t selo . && docker run --rm selo`
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY selo ./selo
COPY selo_v0 ./selo_v0
COPY experiments ./experiments
COPY tests ./tests
RUN pip install --no-cache-dir .
CMD ["python", "-m", "selo_v0", "demo"]
