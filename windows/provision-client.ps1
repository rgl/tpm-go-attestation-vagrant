# copy the swtpm ca certificates to the final destination.
mkdir -Force /opt/swtpm-localca | Out-Null
Copy-item ~/swtpm-localca-cert.pem /opt/swtpm-localca
Copy-item ~/swtpm-localca-rootca-cert.pem /opt/swtpm-localca
