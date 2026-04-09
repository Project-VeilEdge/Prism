// Package mtls provides self-signed CA initialization and node certificate
// issuance for mTLS communication between Prism components.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidDays = 10 * 365 // ~10 years
)

// CA holds the root CA certificate and private key.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// InitCA generates a new self-signed ECDSA P-256 CA certificate and key.
func InitCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mtls: generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Prism"},
			CommonName:   "Prism CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(time.Duration(caValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mtls: create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mtls: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// LoadCA reads a CA certificate and key from PEM files on disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA key: %w", err)
	}

	return ParseCA(certPEM, keyPEM)
}

// ParseCA parses a CA from PEM-encoded certificate and key bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mtls: no PEM block in CA cert")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("mtls: certificate is not a CA")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mtls: no PEM block in CA key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse CA key: %w", err)
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// SaveCA writes the CA certificate and key to disk at the given directory.
// Files: ca-cert.pem, ca-key.pem (key file is mode 0600).
func (ca *CA) SaveCA(dir string) error {
	certFile := filepath.Join(dir, "ca-cert.pem")
	if err := os.WriteFile(certFile, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("mtls: write CA cert: %w", err)
	}

	keyFile := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(keyFile, ca.KeyPEM, 0600); err != nil {
		return fmt.Errorf("mtls: write CA key: %w", err)
	}

	return nil
}

func randomSerial() (*big.Int, error) {
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("mtls: generate serial: %w", err)
	}
	return serial, nil
}
