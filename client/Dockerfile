FROM golang:1.18.2-bullseye as builder
WORKDIR /app
RUN apt-get update && apt-get install -y libtspi-dev
COPY go.* ./
RUN go mod download
RUN go install github.com/google/go-attestation/attest/attest-tool
COPY *.go ./
COPY templates templates
RUN CGO_ENABLED=0 go build -ldflags="-s"

FROM debian:bullseye-slim
EXPOSE 9000
RUN apt-get update && apt-get install -y libtspi1 openssl
WORKDIR /app
COPY --from=builder $HOME/go/bin/attest-tool /usr/local/bin/
COPY --from=builder /app/client ./
ENTRYPOINT ["/app/client"]