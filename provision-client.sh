#!/bin/bash
set -euxo pipefail

# copy the swtpm ca certificates to the final destination.
install -d -m 755 /opt/swtpm-localca
install -m 644 swtpm-localca-cert.pem /opt/swtpm-localca
install -m 644 swtpm-localca-rootca-cert.pem /opt/swtpm-localca

# install the tpm2 tools
apt install -y tpm2-tools
