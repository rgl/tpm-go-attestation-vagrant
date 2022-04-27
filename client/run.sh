#!/bin/bash
set -euxo pipefail

server_ip_address="${1:-10.11.0.101}"; shift || true
client_ip_address="${1:-10.11.0.201}"; shift || true

docker build -t client .

# NB this needs access to:
#       /sys/class/tpm
#       /sys/kernel/security/tpm0/binary_bios_measurements
#       /dev/tpmrm0
# see https://github.com/google/go-attestation/blob/v0.4.3/attest/tpm_linux.go#L33
# see https://github.com/google/go-attestation/blob/v0.4.3/attest/tpm_linux.go#L83-L86
# see https://github.com/google/go-attestation/blob/v0.4.3/attest/tpm_linux.go#L107
docker rm --force client || true
docker run \
    --name client \
    --publish 9000:9000 \
    --privileged \
    --mount type=bind,source=/sys,target=/sys \
    --mount type=bind,source=/opt/swtpm-localca,target=/opt/swtpm-localca,readonly \
    --env APP_NAME="$(hostname)" \
    --env SERVER_BASE_ADDRESS="http://$server_ip_address:8000" \
    --env CLIENT_BASE_ADDRESS="http://$client_ip_address:9000" \
    --restart unless-stopped \
    --detach \
    client

# show information about the tpm.
docker exec client attest-tool info

# do a self-test attestation.
docker exec client attest-tool self-test

# copy attest-tool to the host and install its dependencies.
docker cp client:/usr/local/bin/attest-tool /usr/local/bin/
apt-get install -y libtspi1
