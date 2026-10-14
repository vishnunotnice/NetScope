FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["netscope", "api", "--host", "0.0.0.0", "--port", "8000"]

