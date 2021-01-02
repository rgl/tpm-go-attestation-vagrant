FROM golang:1.15.6-buster as builder
WORKDIR /app
RUN apt-get update && apt-get install -y libtspi-dev
COPY go.* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s"

FROM debian:buster-slim
EXPOSE 8000
RUN apt-get update && apt-get install -y openssl
WORKDIR /app
COPY --from=builder /app/server ./
COPY templates ./templates
ENTRYPOINT ["/app/server"]