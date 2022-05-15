FROM golang:1.18.2-bullseye as builder
WORKDIR /app
RUN apt-get update && apt-get install -y libtspi-dev
COPY go.* ./
RUN go mod download
COPY *.go ./
COPY templates templates
RUN CGO_ENABLED=0 go build -ldflags="-s"

FROM debian:bullseye-slim
EXPOSE 8000
RUN apt-get update && apt-get install -y openssl
WORKDIR /app
COPY --from=builder /app/server ./
ENTRYPOINT ["/app/server"]