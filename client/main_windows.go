package main

import (
	"fmt"
	"os"
	"os/exec"
)

func getCertificateText(der []byte) (string, error) {
	// save the der in a temporary file.
	// NB in windows we cannot use a binary stdin because something messes
	//    it up and openssl fails with:
	//		Could not read certificate from <stdin>
	//		Unable to load certificate
	//    so we use a temporary file instead.
	//    the temporary directory is obtained from syscall.GetTempPath, which
	//    might be at C:\Windows\TEMP.
	//    see https://docs.microsoft.com/en-us/dotnet/api/system.io.path.gettemppath?view=net-6.0&tabs=windows#remarks
	f, err := os.CreateTemp("", "openssl-crt-*.der")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	_, err = f.Write(der)
	if err != nil {
		return "", fmt.Errorf("failed to save temporary file: %w", err)
	}
	f.Close()
	defer os.Remove(f.Name())

	// call openssl.
	cmd := exec.Command("openssl", "x509", "-text", "-inform", "der", "-in", f.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl: %w\n%s", err, output)
	}
	return string(output), nil
}
