# Discovr container image (CLI mode).
# The native desktop needs a display; use headless CLI flags in the container, e.g.
#   docker run --rm -v "$PWD/reports:/reports" discovr --scan-network 10.0.0.0/24 --save yes --out /reports
FROM python:3.13-slim

WORKDIR /app
# Dependencies first so code changes do not invalidate the cached pip layer.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY discovr ./discovr

# All discovery modes run as an unprivileged user.
RUN useradd --create-home discovr
USER discovr

ENTRYPOINT ["python", "-m", "discovr"]
CMD ["--help"]
