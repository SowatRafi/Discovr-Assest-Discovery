# Discovr container image (CLI mode).
# The web UI binds to 127.0.0.1 by design, so inside a container use the CLI flags, e.g.
#   docker run --rm -v "$PWD/reports:/reports" discovr --scan-network 10.0.0.0/24 --save yes --out /reports
FROM python:3.13-slim

# nmap: optional OS fingerprinting (--os-detect); libpcap: passive capture. No compilers needed
# any more now that netifaces is gone.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Dependencies first so code changes do not invalidate the cached pip layer.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY discovr ./discovr

# Least privilege: TCP sweeps and cloud/AD discovery work unprivileged. Passive capture and
# nmap -O need root + raw sockets:  docker run --user root --cap-add NET_RAW --cap-add NET_ADMIN --network host ...
RUN useradd --create-home discovr
USER discovr

ENTRYPOINT ["python", "-m", "discovr"]
CMD ["--help"]
