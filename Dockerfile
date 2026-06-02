FROM python:3.11-slim

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
    binwalk \
    squashfs-tools \
    mtd-utils \
    liblzma-dev \
    zlib1g-dev \
    liblzo2-dev \
    && rm -rf /var/lib/apt/lists/*

# Firmware analysis Python tools
# ubireader: UBI/UBIFS extraction (fixes "ubireader_extract_files not found")
# jefferson: JFFS2 filesystem extraction
# cstruct: ubireader dependency
RUN pip install --no-cache-dir \
    ubi_reader \
    jefferson \
    cstruct

WORKDIR /app

COPY scanner/sin-scanner.go /tmp/sin-scanner.go
RUN mkdir -p /app/bin && \
    cd /tmp && \
    go build -o /app/bin/sin-scanner sin-scanner.go && \
    chmod +x /app/bin/sin-scanner && \
    echo "Go scanner built successfully"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install -e .

ENV SIN_SCANNER_PATH=/app/bin/sin-scanner
