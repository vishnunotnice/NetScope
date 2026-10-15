FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY netscope ./netscope
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["netscope", "api", "--host", "0.0.0.0", "--port", "8000", "--db", "/data/netscope.db"]
