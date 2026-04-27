FROM python:3.11-slim

# Install system deps + Go
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    iputils-ping \
    nmap \
    arp-scan \
    net-tools \
    iptables \
    iproute2 \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build Go scanner
COPY scanner/sin-scanner.go /tmp/sin-scanner.go
RUN mkdir -p /app/bin && \
    cd /tmp && \
    go build -o /app/bin/sin-scanner sin-scanner.go && \
    chmod +x /app/bin/sin-scanner && \
    echo "✅ Go scanner built successfully"

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

ENV SIN_SCANNER_PATH=/app/bin/sin-scanner
