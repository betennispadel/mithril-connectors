FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY phishing_simulation/gophish/go.mod phishing_simulation/gophish/go.sum phishing_simulation/gophish/
RUN cd phishing_simulation/gophish && GOWORK=off go mod download
COPY sdk/ sdk/
COPY phishing_simulation/gophish/ phishing_simulation/gophish/
RUN cd phishing_simulation/gophish && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .

FROM gophish/gophish:latest AS gophish

FROM debian:stable-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=gophish /opt/gophish/ /opt/gophish/
COPY --from=builder /out/connector /usr/local/bin/connector
RUN echo '{"admin_server":{"listen_url":"127.0.0.1:3333","use_tls":true,"cert_path":"gophish_admin.crt","key_path":"gophish_admin.key"},"phish_server":{"listen_url":"0.0.0.0:8080","use_tls":false},"db_name":"sqlite3","db_path":"gophish.db","migrations_prefix":"db/sqlite3","contact_address":"","logging":{"filename":"","level":"info"}}' > /opt/gophish/config.json
ENV GOPHISH_INITIAL_ADMIN_API_TOKEN=imperius-connector-token
ENV GOPHISH_INITIAL_ADMIN_PASSWORD=imperius
RUN useradd -u 10001 -m connector
RUN chown -R connector:connector /opt/gophish
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
