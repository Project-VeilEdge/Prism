package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/pem"
	"fmt"
)

// KeyPair holds an X25519 key pair for HPKE-based ECH decryption.
type KeyPair struct {
	sk       *ecdh.PrivateKey
	pk       *ecdh.PublicKey
	ConfigID uint8  // ECH config_id assigned to this key pair
	Config   []byte // Serialized ECHConfig (set by BuildECHConfig)
}

// KeySet holds the current and previous key pairs for dual-key rotation.
// During key rotation, Previous is kept for >= 2×DNS_TTL to handle stale caches.
type KeySet struct {
	Current  *KeyPair
	Previous *KeyPair // may be nil
}

// GenerateKeyPair generates a fresh X25519 key pair suitable for ECH.
func GenerateKeyPair() (*KeyPair, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	return &KeyPair{sk: sk, pk: sk.PublicKey()}, nil
}

// PrivateKey returns the raw 32-byte X25519 private key.
func (kp *KeyPair) PrivateKey() []byte {
	return kp.sk.Bytes()
}

// PublicKey returns the raw 32-byte X25519 public key.
func (kp *KeyPair) PublicKey() []byte {
	return kp.pk.Bytes()
}

// MarshalPrivateKeyPEM encodes the private key in PEM format.
func (kp *KeyPair) MarshalPrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ECH PRIVATE KEY",
		Bytes: kp.sk.Bytes(),
	})
}

// MarshalPublicKeyPEM encodes the public key in PEM format.
func (kp *KeyPair) MarshalPublicKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ECH PUBLIC KEY",
		Bytes: kp.pk.Bytes(),
	})
}

// ParsePrivateKeyPEM decodes a PEM-encoded X25519 private key.
func ParsePrivateKeyPEM(data []byte) (*KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "ECH PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	sk, err := ecdh.X25519().NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 private key: %w", err)
	}
	return &KeyPair{sk: sk, pk: sk.PublicKey()}, nil
}
