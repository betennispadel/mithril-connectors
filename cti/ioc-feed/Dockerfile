FROM golang:1.24-alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o connector .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN adduser -u 10001 -D connector
COPY --from=builder /build/connector /usr/local/bin/connector
USER connector
ENTRYPOINT ["/usr/local/bin/connector"]
