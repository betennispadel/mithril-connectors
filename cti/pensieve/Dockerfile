FROM golang:1.26-alpine AS builder
WORKDIR /build

# Copy SDK first (dependency)
COPY sdk/ /build/sdk/

# Copy connector source
COPY cti/pensieve/ /build/connector/
WORKDIR /build/connector

# Fix replace directive to match Docker layout
RUN go mod edit -replace github.com/betennispadel/mithril-connectors/sdk=/build/sdk
RUN go mod download
RUN CGO_ENABLED=0 go build -o /connector .

# ── Runtime ────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Install VoidAccess with API mode (FastAPI + uvicorn) + other dependencies
RUN pip install --no-cache-dir "voidaccess[api]" opensquat telethon "httpx[socks]" && \
    python -m spacy download en_core_web_sm && \
    apt-get update && apt-get install -y --no-install-recommends \
      tor ca-certificates postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Patch aiohttp to honor HTTP_PROXY env vars
COPY cti/pensieve/sitecustomize.py /usr/local/lib/python3.12/site-packages/sitecustomize.py

COPY --from=builder /connector /usr/local/bin/connector

ENTRYPOINT ["connector"]
