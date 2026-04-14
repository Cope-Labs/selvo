# Multi-stage build:
#   stage 1 (builder) has .git so hatch-vcs can read the tag for __version__,
#   stage 2 installs the resulting wheel and ships only the runtime deps.
#
# Single-stage was simpler but caused the in-container selvo to report the
# fallback version (1.0.0) instead of the real tag, since .git wasn't copied
# in. Multi-stage keeps the runtime image small while preserving versioning.

FROM python:3.12-slim AS builder

WORKDIR /build

# git is required for hatch-vcs to read the tag.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Copy the full tree so hatch-vcs sees a non-dirty working tree (any tracked
# file missing from the build context shows up as a deletion and adds the
# .d<date> dirty suffix to the version). .dockerignore prunes out the obvious
# dev-only directories so the build context stays small.
COPY . ./

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist


FROM python:3.12-slim

LABEL org.opencontainers.image.title="selvo-api" \
      org.opencontainers.image.description="selvo Linux dependency risk analysis REST API" \
      org.opencontainers.image.source="https://github.com/Cope-Labs/selvo"

WORKDIR /app

# Runtime system deps:
#   curl   — health checks
#   git    — upstream analysis
#   skopeo — daemon-less OCI image pulls for /api/v1/scan/image
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        skopeo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /dist/*.whl /tmp/

# Install the wheel built in stage 1 (real version baked into _version.py).
RUN WHEEL=$(ls /tmp/selvo-*.whl) \
    && pip install --no-cache-dir "${WHEEL}[api]" \
    && rm "$WHEEL"

# Cache directory expected at runtime.
RUN mkdir -p /root/.cache/selvo

EXPOSE 8765

# Exec form so signals propagate (tini is not in the slim image).
CMD ["selvo-api", "--host", "0.0.0.0", "--port", "8765"]
