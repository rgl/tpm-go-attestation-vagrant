# Usage

Install the [Ubuntu 20.04 UEFI vagrant box](https://github.com/rgl/ubuntu-vagrant).

Install the [Windows 2022 UEFI vagrant box](https://github.com/rgl/windows-vagrant).

Install the [swtpm](https://github.com/stefanberger/swtpm) packages as described in [swtpm-vagrant](https://github.com/rgl/swtpm-vagrant).

Start the environment then do a self-test attestation:

```bash
# start the server.
time vagrant up --provider=libvirt --no-destroy-on-error --no-tty server
# start the ubuntu client.
time vagrant up --provider=libvirt --no-destroy-on-error --no-tty client0
# enter the envirment.
vagrant ssh client0
# switch to root.
sudo -i
# show information about the tpm.
attest-tool info
# show the swtpm root ca certificate (this signs the swtpm ca).
openssl x509 -noout -text -in /opt/swtpm-localca/swtpm-localca-rootca-cert.pem
# show the swtpm ca intermediate certificate (this signs the tpm ek).
openssl x509 -noout -text -in /opt/swtpm-localca/swtpm-localca-cert.pem
# list the tpm endorsement keys (ek) certificates.
attest-tool list-eks | openssl x509 -noout -text
# do a self-test attestation.
attest-tool self-test
```

Access the `server` page to see the known clients:

  http://10.11.0.101:8000

Click one of the clients to go to its Remove Attestation page.

Click the "Start Remote Attestation" button and go through the remote attestation steps.


# Real-World Projects

* [Secure Production Identity Framework For Everyone (SPIFFE)](https://github.com/spiffe/spiffe)
* [SPIFFE Runtime Environment (SPIRE)](https://github.com/spiffe/spire)
  * [TPM2 based node attestation plugin](https://github.com/bloomberg/spire-tpm-plugin)
* [Keylime (Bootstrap & Maintain Trust on the Edge / Cloud and IoT)](https://keylime.dev/)

# References

* [Go-Attestation library](https://github.com/google/go-attestation)
  * [attest-tool self-test](https://github.com/google/go-attestation/blob/v0.4.3/attest/attest-tool/attest-tool.go#L119-L132)
* [Remote Attestation with TPM (in the context of SPIRE)](https://github.com/bloomberg/spire-tpm-plugin/blob/master/TPM.md)
* [Remote Attestation With TPM2 Tools](https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html)
* [tpm-js (experiment with a software Trusted Platform Module (TPM) in your browser)](https://google.github.io/tpm-js/)
* [Using the TPM - It's Not Rocket Science (Anymore) - Johannes Holland & Peter Huewe](https://www.youtube.com/watch?v=XwaSyHJIos8)
