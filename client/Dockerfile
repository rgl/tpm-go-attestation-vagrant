FROM golang:1.15.6-buster as builder
WORKDIR /app
RUN apt-get update && apt-get install -y libtspi-dev
COPY go.* ./
RUN go mod download
RUN go get github.com/google/go-attestation/attest/attest-tool
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s"

FROM debian:buster-slim
EXPOSE 9000
RUN apt-get update && apt-get install -y libtspi1 openssl
WORKDIR /app
COPY --from=builder /go/bin/attest-tool /usr/local/bin/
COPY --from=builder /app/client ./
COPY templates ./templates
ENTRYPOINT ["/app/client"]