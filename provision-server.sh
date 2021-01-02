#!/bin/bash
set -euxo pipefail

# copy the swtpm ca certificates to the final destination.
install -d -m 755 /opt/tpm-certs
install -m 644 swtpm-localca-cert.pem /opt/tpm-certs
install -m 644 swtpm-localca-rootca-cert.pem /opt/tpm-certs
