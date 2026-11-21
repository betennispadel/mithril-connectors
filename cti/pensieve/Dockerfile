FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY ../sdk /build/sdk

WORKDIR /build/connector
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /connector .

# ── Runtime ────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

RUN pip install --no-cache-dir voidaccess && \
    apt-get update && apt-get install -y --no-install-recommends tor ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /connector /usr/local/bin/connector

ENTRYPOINT ["connector"]
