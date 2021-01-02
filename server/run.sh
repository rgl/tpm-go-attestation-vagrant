#!/bin/bash
set -euxo pipefail

server_ip_address="${1:-10.11.0.101}"; shift || true
client_base_addresses="${1:-http://10.11.0.201:9000,http://10.11.0.202:9000}"; shift || true

docker build -t server .

docker rm --force server || true
docker run \
    --name server \
    --publish 8000:8000 \
    --mount type=bind,source=/opt/tpm-certs,target=/opt/tpm-certs,readonly \
    --env APP_NAME="$(hostname)" \
    --env SERVER_BASE_ADDRESS="http://$server_ip_address:8000" \
    --env CLIENT_BASE_ADDRESSES="$client_base_addresses" \
    --restart unless-stopped \
    --detach \
    server
