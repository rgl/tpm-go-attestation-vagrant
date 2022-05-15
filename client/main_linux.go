package main

import (
	"bytes"
	"fmt"
	"os/exec"
)

func getCertificateText(der []byte) (string, error) {
	cmd := exec.Command("openssl", "x509", "-text", "-inform", "der")
	cmd.Stdin = bytes.NewReader(der)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl: %w\n%s", err, output)
	}
	return string(output), nil
}
