FROM python:3.11-slim

LABEL org.opencontainers.image.title="selvo-scan"
LABEL org.opencontainers.image.description="selvo Linux supply-chain risk scanner"
LABEL org.opencontainers.image.source="https://github.com/sethc5/codup"

# Install system deps for optional container scanning
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Install selvo — pinned for hermeticity
RUN pip install --no-cache-dir "selvo>=0.1.0"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
