package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"prism/pkg/mtls"
)

type MITMIssuer struct {
	ca    *mtls.CA
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]tls.Certificate
	group singleflight.Group
}

func NewMITMIssuer(caCertPath, caKeyPath string, ttl time.Duration) (*MITMIssuer, error) {
	ca, err := mtls.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}

	return &MITMIssuer{
		ca:    ca,
		ttl:   ttl,
		cache: make(map[string]tls.Certificate),
	}, nil
}

func (i *MITMIssuer) CertificateFor(host string) (*tls.Certificate, error) {
	// Fast path: check cache
	i.mu.Lock()
	if cert, ok := i.cache[host]; ok {
		leaf := cert.Leaf
		if leaf == nil && len(cert.Certificate) > 0 {
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				i.mu.Unlock()
				return nil, fmt.Errorf("parse cached leaf cert: %w", err)
			}
			cert.Leaf = parsed
			leaf = parsed
			i.cache[host] = cert
		}
		if leaf != nil && leaf.NotAfter.After(time.Now()) {
			cached := cert
			i.mu.Unlock()
			return &cached, nil
		}
		delete(i.cache, host)
	}
	i.mu.Unlock()

	// Slow path: singleflight-protected generation
	val, err, _ := i.group.Do(host, func() (interface{}, error) {
		// Double-check cache (another goroutine may have populated it)
		i.mu.Lock()
		if cert, ok := i.cache[host]; ok {
			leaf := cert.Leaf
			if leaf == nil && len(cert.Certificate) > 0 {
				parsed, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					i.mu.Unlock()
					return nil, fmt.Errorf("parse cached leaf cert: %w", err)
				}
				cert.Leaf = parsed
				leaf = parsed
				i.cache[host] = cert
			}
			if leaf != nil && leaf.NotAfter.After(time.Now()) {
				cached := cert
				i.mu.Unlock()
				return &cached, nil
			}
			delete(i.cache, host)
		}
		i.mu.Unlock()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate leaf key: %w", err)
		}

		serial, err := randomMITMSerial()
		if err != nil {
			return nil, err
		}

		template := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				Organization: []string{"Prism"},
				CommonName:   host,
			},
			DNSNames:    []string{host},
			NotBefore:   time.Now().Add(-1 * time.Minute),
			NotAfter:    time.Now().Add(i.ttl),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, i.ca.Cert, &key.PublicKey, i.ca.Key)
		if err != nil {
			return nil, fmt.Errorf("sign leaf cert: %w", err)
		}

		leaf, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parse leaf cert: %w", err)
		}

		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal leaf key: %w", err)
		}

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load leaf keypair: %w", err)
		}
		tlsCert.Leaf = leaf

		i.mu.Lock()
		i.cache[host] = tlsCert
		i.mu.Unlock()

		return &tlsCert, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*tls.Certificate), nil
}

// CA returns the issuer's CA certificate.
func (i *MITMIssuer) CA() *x509.Certificate {
	return i.ca.Cert
}

func randomMITMSerial() (*big.Int, error) {
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
