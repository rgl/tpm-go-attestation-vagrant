package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"

	"github.com/google/go-attestation/attest"
)

var (
	//go:embed templates/*
	templateFiles embed.FS
	templates     *template.Template
)

type indexData struct {
	Title               string
	ClientBaseAddresses []string
}

type remoteAttestationStartData struct {
	Title                  string
	EKSubject              string
	EKIssuer               string
	EK                     string
	ServerBaseAddress      string
	ClientChallengeAddress string
	AttestationChallenge   string
}

type remoteAttestationValidationResultData struct {
	Title     string
	EKSubject string
	EKIssuer  string
	EK        string
}

type AttestationData struct {
	EK          []byte
	AK          *attest.AttestationParameters
	ClientState []byte
}

type AttestationChallenge struct {
	EC          *attest.EncryptedCredential
	ClientState []byte
	ServerState []byte
}

type AttestationChallengeResponse struct {
	Secret      []byte
	ServerState []byte
}

type attestationChallengeState struct {
	EK     []byte
	Secret []byte
}

type sealedCiphertext struct {
	Nonce      []byte
	Ciphertext []byte
}

// see https://golang.org/pkg/crypto/cipher/#example_NewGCM_encrypt
func seal(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AES cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create GCM cipher: %v", err)
	}

	// NB Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Failed to read nonce random data: %v", err)
	}

	// NB this is the most inefficient seal in the world.
	return json.Marshal(&sealedCiphertext{
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	})
}

func unseal(key []byte, data []byte) ([]byte, error) {
	var seal sealedCiphertext
	err := json.Unmarshal(data, &seal)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal seal data: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AES cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create GCM cipher: %v", err)
	}

	return aead.Open(nil, seal.Nonce, seal.Ciphertext, nil)
}

func getCertificateText(der []byte) (string, error) {
	cmd := exec.Command("openssl", "x509", "-text", "-inform", "der")
	cmd.Stdin = bytes.NewReader(der)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func generateAttestationChallenge(sealKey []byte, attestationData *AttestationData) (*AttestationChallenge, error) {
	ekCertificate, err := attest.ParseEKCertificate(attestationData.EK)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the credential activation challenge: %v", err)
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekCertificate.PublicKey,
		AK:         *attestationData.AK,
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the credential activation challenge: %v", err)
	}

	attestationChallengeState, err := json.Marshal(&attestationChallengeState{
		EK:     attestationData.EK,
		Secret: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal attestation challenge context: %v", err)
	}

	serverState, err := seal(sealKey, attestationChallengeState)
	if err != nil {
		return nil, fmt.Errorf("Failed to seal the attestation challenge context: %v", err)
	}

	return &AttestationChallenge{
		EC:          ec,
		ClientState: attestationData.ClientState,
		ServerState: serverState,
	}, nil
}

func validateAttestationChallengeResponse(sealKey []byte, attestationChallengeResponse *AttestationChallengeResponse) ([]byte, error) {
	serverState, err := unseal(sealKey, attestationChallengeResponse.ServerState)
	if err != nil {
		return nil, fmt.Errorf("Failed to unseal server state: %v", err)
	}

	var attestationChallengeContext attestationChallengeState
	err = json.Unmarshal(serverState, &attestationChallengeContext)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal server state: %v", err)
	}

	if !bytes.Equal(attestationChallengeResponse.Secret, attestationChallengeContext.Secret) {
		return nil, fmt.Errorf("Failed to validate secret")
	}

	return attestationChallengeContext.EK, nil
}

func main() {
	log.SetFlags(0)

	var listenAddress = flag.String("listen", ":8000", "Listen address.")

	flag.Parse()

	if flag.NArg() != 0 {
		flag.Usage()
		log.Fatalf("\nYou MUST NOT pass any positional arguments")
	}

	templates = template.Must(template.ParseFS(templateFiles, "templates/*"))

	// this AEAD AES key is used to seal state data that we send to the
	// client (because HTTP is stateless).
	// NB this must be 128 or 256 bit.
	sealKey := make([]byte, 128/8)
	_, err := rand.Read(sealKey)
	if err != nil {
		log.Fatalf("Failed to read seal key random data: %v", err)
	}

	// TODO properly verify the certificate.
	// 		NB also take into account:
	//			3.2.2.6.2.1.2.5 Processing Rules for an Initial Key Attestation Request https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/820e4b9e-d3fc-4641-8bb5-9063b0744391
	//			3.2.2.6.2.1.2.5.1 Processing Rules for Key Attestation Based on Certificates at https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e406bafe-5882-437d-a68a-b8427f62bf84
	// NB crypto/x509 library does not handle the 2.23.133.8.1 (tcg-kp-EKCertificate) Extended Key Usage.
	// NB crypto/x509 library does not handle the following critical extension:
	//		X509v3 Subject Alternative Name: critical
	//			DirName:/2.23.133.2.1=id:00001014/2.23.133.2.2=swtpm/2.23.133.2.3=id:20170619

	// validate the ek certificate sent by the client.
	// generate attestation challenge and send it to the client.
	http.HandleFunc("/remote-attestation/start", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%s", dump)

		var attestationData AttestationData
		err := json.Unmarshal([]byte(r.FormValue("attestation-data")), &attestationData)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to parse attestation-data: %v", err),
				http.StatusBadRequest)
			return
		}

		ek := attestationData.EK
		ekCertificate, err := attest.ParseEKCertificate(ek)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to parse the EK certificate: %v", err),
				http.StatusBadRequest)
			return
		}

		ekCertificateText, err := getCertificateText(ek)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to validate attestation-challenge-response context: %v", err),
				http.StatusBadRequest)
			return
		}

		attestationChallenge, err := generateAttestationChallenge(
			sealKey,
			&attestationData)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to generate attestation-challenge: %v", err),
				http.StatusInternalServerError)
			return
		}

		attestationChallengeBytes, err := json.Marshal(attestationChallenge)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to marshal attestation-challenge: %v", err),
				http.StatusInternalServerError)
			return
		}

		err = templates.ExecuteTemplate(w, "remote-attestation-start.html", remoteAttestationStartData{
			Title:                  fmt.Sprintf("%s: Start Remote Attestation Challenge", os.Getenv("APP_NAME")),
			ServerBaseAddress:      os.Getenv("SERVER_BASE_ADDRESS"),
			ClientChallengeAddress: r.FormValue("challenge-address"),
			AttestationChallenge:   string(attestationChallengeBytes),
			EK:                     ekCertificateText,
			EKSubject:              ekCertificate.Subject.String(),
			EKIssuer:               ekCertificate.Issuer.String(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// validates the challenge secret sent by the client.
	http.HandleFunc("/remote-attestation/secret", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%s", dump)

		var attestationChallengeResponse AttestationChallengeResponse
		err := json.Unmarshal([]byte(r.FormValue("attestation-challenge-response")), &attestationChallengeResponse)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to unmarshal attestation-challenge-response: %v", err),
				http.StatusBadRequest)
			return
		}

		ek, err := validateAttestationChallengeResponse(
			sealKey,
			&attestationChallengeResponse)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to validate attestation-challenge-response: %v", err),
				http.StatusBadRequest)
			return
		}

		ekCertificate, err := attest.ParseEKCertificate(ek)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to parse the EK certificate: %v", err),
				http.StatusBadRequest)
			return
		}

		ekCertificateText, err := getCertificateText(ek)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to validate attestation-challenge-response context: %v", err),
				http.StatusBadRequest)
			return
		}

		err = templates.ExecuteTemplate(w, "remote-attestation-secret.html", remoteAttestationValidationResultData{
			Title:     fmt.Sprintf("%s: Remote Attestation Succeeded", os.Getenv("APP_NAME")),
			EK:        ekCertificateText,
			EKSubject: ekCertificate.Subject.String(),
			EKIssuer:  ekCertificate.Issuer.String(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%s", dump)

		err := templates.ExecuteTemplate(w, "index.html", indexData{
			Title:               os.Getenv("APP_NAME"),
			ClientBaseAddresses: strings.Split(os.Getenv("CLIENT_BASE_ADDRESSES"), ","),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	fmt.Printf("Listening at http://%s\n", *listenAddress)

	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatalf("Failed to ListenAndServe: %v", err)
	}
}
