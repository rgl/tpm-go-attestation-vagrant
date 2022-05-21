package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/smallstep/certinfo"
)

var (
	//go:embed templates/*
	templateFiles embed.FS
	templates     *template.Template
)

type indexData struct {
	Title              string
	ServerBaseAddress  string
	ClientBaseAddress  string
	TPMEndorsementKeys []nameValuePair
	SWTPMCertificates  []nameValuePair
}

type remoteAttestationStartData struct {
	Title             string
	ServerBaseAddress string
	ClientBaseAddress string
	AttestationData   string
}

type remoteAttestationChallengeData struct {
	Title                        string
	ServerSecretAddress          string
	AttestationChallengeResponse string
}

type nameValuePair struct {
	Name  string
	Value string
}

type nameValuePairs []nameValuePair

func (a nameValuePairs) Len() int      { return len(a) }
func (a nameValuePairs) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a nameValuePairs) Less(i, j int) bool {
	if a[i].Name < a[j].Name {
		return true
	}
	if a[i].Name > a[j].Name {
		return false
	}
	return a[i].Value < a[j].Value
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

func getCertificateFileText(path string) (string, error) {
	pemCrt, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", path, err)
	}
	block, _ := pem.Decode([]byte(pemCrt))
	if block == nil {
		return "", fmt.Errorf("failed to decode pem from file %s", path)
	}
	return getCertificateText(block.Bytes)
}

func getCertificateText(der []byte) (string, error) {
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	text, err := certinfo.CertificateText(crt)
	if err != nil {
		return "", fmt.Errorf("failed to convert certificate to text: %w", err)
	}
	pemCrt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return text + string(pemCrt), nil
}

func getTPMEndorsementKeys() []nameValuePair {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return []nameValuePair{{Name: "ERROR", Value: fmt.Sprintf("Error opening the TPM: %v", err)}}
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		return []nameValuePair{{Name: "ERROR", Value: fmt.Sprintf("Error getting EKs from TPM: %v", err)}}
	}

	result := make([]nameValuePair, 0)
	for i, ek := range eks {
		name := fmt.Sprintf("EK #%d", i)
		value, err := getCertificateText(ek.Certificate.Raw)
		if err != nil {
			value = fmt.Sprintf("ERROR: %v\n%s",
				err,
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ek.Certificate.Raw}))
		}
		result = append(result, nameValuePair{name, string(value)})
	}

	return result
}

func getSWTPMCertificates() []nameValuePair {
	result := make([]nameValuePair, 0)
	paths, _ := filepath.Glob("/opt/swtpm-localca/*-cert.pem")
	for _, p := range paths {
		name := strings.ReplaceAll(filepath.Base(p), "-cert.pem", "")
		value, err := getCertificateFileText(p)
		if err != nil {
			value = fmt.Sprintf("ERROR: %v", err)
		}
		result = append(result, nameValuePair{name, string(value)})
	}
	sort.Sort(nameValuePairs(result))
	return result
}

func generateAttestationData(sealKey []byte) (*AttestationData, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to open the TPM: %v", err)
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the EKs: %v", err)
	}
	// NB as of go-attestation v0.2.2 only RSA keys are supported by ActivateCredential.
	var ekCertificateBytes []byte
	for _, ek := range eks {
		if ek.Certificate != nil && ek.Certificate.PublicKeyAlgorithm.String() == "RSA" {
			ekCertificateBytes = ek.Certificate.Raw
		}
	}
	if len(ekCertificateBytes) == 0 {
		return nil, fmt.Errorf("Failed to find an EK with a RSA-based certificate: %v", err)
	}

	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the AK: %v", err)
	}
	defer ak.Close(tpm)

	attestationParameters := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal the AK: %v", err)
	}

	clientState, err := seal(sealKey, akBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to seal attestation data client state: %v", err)
	}

	return &AttestationData{
		EK:          ekCertificateBytes,
		AK:          &attestationParameters,
		ClientState: clientState,
	}, nil
}

func generateAttestationChallengeResponse(sealKey []byte, attestationChallenge *AttestationChallenge) (*AttestationChallengeResponse, error) {
	akBytes, err := unseal(sealKey, attestationChallenge.ClientState)
	if err != nil {
		return nil, fmt.Errorf("Failed to unseal client state: %v", err)
	}

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to open the TPM: %v", err)
	}
	defer tpm.Close()

	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the AK: %v", err)
	}
	defer ak.Close(tpm)

	secret, err := ak.ActivateCredential(tpm, *attestationChallenge.EC)
	if err != nil {
		return nil, fmt.Errorf("Failed to activate credential: %v", err)
	}

	return &AttestationChallengeResponse{
		Secret:      secret,
		ServerState: attestationChallenge.ServerState,
	}, nil
}

func main() {
	log.SetFlags(0)

	var listenAddress = flag.String("listen", ":9000", "Listen address.")

	flag.Parse()

	if flag.NArg() != 0 {
		flag.Usage()
		log.Fatalf("\nYou MUST NOT pass any positional arguments")
	}

	templates = template.Must(template.ParseFS(templateFiles, "templates/*"))

	// this AEAD AES key is used to seal state data that we send to the
	// server (because HTTP is stateless).
	// NB this must be 128 or 256 bit.
	sealKey := make([]byte, 128/8)
	_, err := rand.Read(sealKey)
	if err != nil {
		log.Fatalf("Failed to read seal key random data: %v", err)
	}

	// generate ak, send the ak attestation parameters and ek certificate to the server.
	http.HandleFunc("/remote-attestation/start", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%s", dump)

		attestationData, err := generateAttestationData(sealKey)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to generate attestation-data: %v", err),
				http.StatusInternalServerError)
			return
		}

		attestationDataBytes, err := json.Marshal(attestationData)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to marshal attestation-data: %v", err),
				http.StatusInternalServerError)
			return
		}

		err = templates.ExecuteTemplate(w, "remote-attestation-start.html", remoteAttestationStartData{
			Title:             fmt.Sprintf("@%s: Start Remote Attestation", os.Getenv("APP_NAME")),
			ServerBaseAddress: os.Getenv("SERVER_BASE_ADDRESS"),
			ClientBaseAddress: os.Getenv("CLIENT_BASE_ADDRESS"),
			AttestationData:   string(attestationDataBytes),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// decrypt challenge secret, send the decrypted challenge secret to the server.
	http.HandleFunc("/remote-attestation/challenge", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%s", dump)

		var attestationChallenge AttestationChallenge
		err := json.Unmarshal([]byte(r.FormValue("attestation-challenge")), &attestationChallenge)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to unmarshal attestation-challenge: %v", err),
				http.StatusInternalServerError)
			return
		}

		attestationChallengeResponse, err := generateAttestationChallengeResponse(sealKey, &attestationChallenge)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to generate attestation-challenge-response: %v", err),
				http.StatusInternalServerError)
			return
		}

		attestationChallengeResponseBytes, err := json.Marshal(attestationChallengeResponse)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to marshal attestation-challenge-response: %v", err),
				http.StatusInternalServerError)
			return
		}

		err = templates.ExecuteTemplate(w, "remote-attestation-challenge.html", remoteAttestationChallengeData{
			Title:                        fmt.Sprintf("@%s: Reply to Remote Attestation Challenge", os.Getenv("APP_NAME")),
			ServerSecretAddress:          r.FormValue("attestation-secret-address"),
			AttestationChallengeResponse: string(attestationChallengeResponseBytes),
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
			Title:              fmt.Sprintf("@%s", os.Getenv("APP_NAME")),
			ServerBaseAddress:  os.Getenv("SERVER_BASE_ADDRESS"),
			ClientBaseAddress:  os.Getenv("CLIENT_BASE_ADDRESS"),
			SWTPMCertificates:  getSWTPMCertificates(),
			TPMEndorsementKeys: getTPMEndorsementKeys(),
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
