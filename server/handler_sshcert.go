package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/go-attestation/attest"

	"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/puiterwijk/dendraeck/shared/types"
)

func validateIntermediateCertificate(rawtoken string) (*intermediateCertInfo, error) {
	// Validate that this is an intermediate cert by the correct service, and still valid
	token, err := jwt.ParseSigned(rawtoken)
	if err != nil {
		return nil, fmt.Errorf("Error parsing intermediate cert: %s", err)
	}

	var claims jwt.Claims
	var intcertinfo intermediateCertInfo
	err = token.Claims(intermediatePublicKey, &claims, &intcertinfo)
	if err != nil {
		return nil, fmt.Errorf("Error parsing intermediate certificate: %s", err)
	}
	err = claims.Validate(jwt.Expected{
		Issuer: serviceinfo.Root,
	})
	if err != nil {
		return nil, fmt.Errorf("Error with the intermediate certificate: %s", err)
	}
	if intcertinfo.Username != claims.Subject {
		return nil, fmt.Errorf("Username (%s) does not match subject (%s)", intcertinfo.Username, claims.Subject)
	}
	return &intcertinfo, nil
}

func generateSSHCert(request *types.SSHCertRequest, sub string) ([]byte, error) {
	pubkey, err := ssh.ParsePublicKey(request.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error parsing public key: %s", err)
	}

	cert := new(ssh.Certificate)
	cert.CertType = ssh.UserCert
	cert.Extensions = make(map[string]string)
	cert.Key = pubkey
	cert.ValidAfter = uint64(time.Now().Unix())
	cert.ValidBefore = uint64(time.Now().Add(certValidity).Unix())
	cert.ValidPrincipals = []string{sub}

	// TODO: Fill cert with extra attributes
	if addGitHubOption {
		cert.Extensions["login@github.com"] = sub
	}

	err = cert.SignCert(rand.Reader, sshSigner)
	if err != nil {
		return nil, fmt.Errorf("Error signing certificate: %s", err)
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

func sshCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		returnAPIError(w, "Invalid request method")
		return
	}

	var req types.SSHCertRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	r.Body.Close()
	if err != nil {
		returnAPIError(w, "Invalid request")
		return
	}

	intcert, err := validateIntermediateCertificate(req.IntermediateCert)
	if err != nil {
		fmt.Println("Invalid intermediate cert:", err)
		returnAPIError(w, "Intermediate certificate invalid")
		return
	}

	log.Printf("Signing SSH key for user %s and server %s", intcert.Username, req.Servername)
	cert, err := generateSSHCert(&req, intcert.Username)
	if err != nil {
		fmt.Println("Error generating SSH cert: ", err)
		returnAPIError(w, "Error generating SSH cert")
		return
	}

	var certresp types.SSHCertResponse
	if serviceinfo.Requirements.TPM {
		if err := encryptSSHCert(intcert, &certresp, cert); err != nil {
			fmt.Println("Error encrypting SSH cert: ", err)
			returnAPIError(w, "Error encrypting certificate")
			return
		}
	} else {
		certresp.Certificate.Contents = cert
	}

	returnAPISuccess(w, certresp)
}

func encryptSSHCert(intcert *intermediateCertInfo, certresp *types.SSHCertResponse, cert []byte) error {
	act := new(attest.ActivationParameters)
	act.TPMVersion = intcert.TPMVersion
	act.AIK = intcert.AIK
	ekpub, err := x509.ParsePKCS1PublicKey(intcert.EKPublicKey)
	if err != nil {
		return fmt.Errorf("Error getting EKPub: %s", err)
	}
	act.EK = ekpub
	secret, ec, err := act.Generate()
	if err != nil {
		return fmt.Errorf("Error generating activation secret: %s", err)
	}

	certresp.Certificate.CryptedContents.EncryptedCredential = ec

	blockcipher, err := aes.NewCipher(secret)
	if err != nil {
		return fmt.Errorf("Error creating AES cipher: %s", err)
	}
	aead, err := cipher.NewGCM(blockcipher)
	if err != nil {
		return fmt.Errorf("Error creating GCM cipher: %s", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("Error creating nonce: %s", err)
	}

	certresp.Certificate.CryptedContents.Nonce = nonce
	certresp.Certificate.CryptedContents.Contents = aead.Seal(nil, nonce, cert, nil)
	certresp.Certificate.Contents = nil
	certresp.Certificate.IsCrypted = true

	return nil
}
