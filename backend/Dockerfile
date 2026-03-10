FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables iproute2 iputils-ping curl jq conntrack && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN useradd -r -s /usr/sbin/nologin -d /app macflow && \
    chown -R macflow:macflow /app

COPY . /app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:18080/api/auth/status || exit 1

EXPOSE 18080
USER macflow
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "18080"]
