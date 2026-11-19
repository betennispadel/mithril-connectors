# Stage 1: Build Go binary
FROM golang:1.24-alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o connector .

# Stage 2: Semgrep runtime
FROM python:3.12-slim
RUN pip install --no-cache-dir semgrep==1.90.0 &&     apt-get update && apt-get install -y --no-install-recommends git &&     rm -rf /var/lib/apt/lists/*
RUN useradd -u 10001 -m connector
COPY --from=builder /build/connector /usr/local/bin/connector
USER connector
ENTRYPOINT ["/usr/local/bin/connector"]
