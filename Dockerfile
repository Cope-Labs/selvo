FROM python:3.14-slim

LABEL org.opencontainers.image.title="selvo-api" \
      org.opencontainers.image.description="selvo Linux dependency risk analysis REST API" \
      org.opencontainers.image.source="https://github.com/sethc5/selvo"

WORKDIR /app

# Install system dependencies needed by some analysis modules.
#   curl   — health checks
#   git    — upstream analysis
#   skopeo — daemon-less OCI image pulls for /api/v1/scan/image. Without it
#            the scan-image endpoint only works in self-hosted deployments
#            where /var/run/docker.sock is mounted.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        skopeo \
    && rm -rf /var/lib/apt/lists/*

# Copy full source so pip install . works
COPY pyproject.toml README.md ./
COPY selvo/ ./selvo/

# Install Python package with the [api] extra (FastAPI + uvicorn).
RUN pip install --no-cache-dir ".[api]"

# Ensure the cache directory exists and is writable at runtime.
RUN mkdir -p /root/.cache/selvo

EXPOSE 8765

# tini is not bundled in the slim image; use exec form so signals propagate.
CMD ["selvo-api", "--host", "0.0.0.0", "--port", "8765"]
