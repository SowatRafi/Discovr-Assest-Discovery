# 1. Start from lightweight Python image
FROM python:3.11-slim

# 2. Install system dependencies (Nmap, Scapy dependencies, build tools)
RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    libpcap-dev \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 3. Set working directory inside the container
WORKDIR /app

# 4. Copy Discovr source code into the container
COPY . /app

# 5. Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 6. Default command (you can override when running)
ENTRYPOINT ["python", "-m", "discovr.cli"]
