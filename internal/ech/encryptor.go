package ech

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
)

// Encryptor creates ECH-wrapped ClientHellos for the prism-client.
// It is the inverse of KeySet.Decrypt: given a plaintext ClientHello and an
// ECHConfig (from the target's DNS HTTPS record), it produces an outer
// ClientHello with the inner CH encrypted inside an ECH extension (0xfe0d).
type Encryptor struct {
	// The ECHConfig obtained from the server's DNS HTTPS record.
	config     []byte
	configID   uint8
	publicKey  *ecdh.PublicKey
	publicName string // public_name from ECHConfig (goes into outer SNI)
}

// NewEncryptor creates an Encryptor from a serialized ECHConfig.
// The ECHConfig is typically obtained from a DNS HTTPS record.
func NewEncryptor(echConfig []byte) (*Encryptor, error) {
	if len(echConfig) < 4 {
		return nil, errors.New("ech/encryptor: ECHConfig too short")
	}

	// Parse version.
	version := binary.BigEndian.Uint16(echConfig[0:2])
	if version != echConfigVersion {
		return nil, fmt.Errorf("ech/encryptor: unsupported ECHConfig version 0x%04x", version)
	}

	contentsLen := int(binary.BigEndian.Uint16(echConfig[2:4]))
	if 4+contentsLen > len(echConfig) {
		return nil, errors.New("ech/encryptor: ECHConfig contents truncated")
	}

	contents := echConfig[4 : 4+contentsLen]
	off := 0

	// config_id (1 byte)
	if off >= len(contents) {
		return nil, errors.New("ech/encryptor: truncated config_id")
	}
	configID := contents[off]
	off++

	// kem_id (2 bytes)
	if off+2 > len(contents) {
		return nil, errors.New("ech/encryptor: truncated kem_id")
	}
	kemID := binary.BigEndian.Uint16(contents[off:])
	off += 2
	if kemID != KEMX25519HKDFSHA256 {
		return nil, fmt.Errorf("ech/encryptor: unsupported KEM 0x%04x", kemID)
	}

	// public_key (length-prefixed)
	if off+2 > len(contents) {
		return nil, errors.New("ech/encryptor: truncated public_key length")
	}
	pkLen := int(binary.BigEndian.Uint16(contents[off:]))
	off += 2
	if off+pkLen > len(contents) {
		return nil, errors.New("ech/encryptor: truncated public_key")
	}
	pkBytes := contents[off : off+pkLen]
	off += pkLen

	pk, err := ecdh.X25519().NewPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("ech/encryptor: invalid public key: %w", err)
	}

	// cipher_suites (length-prefixed)
	if off+2 > len(contents) {
		return nil, errors.New("ech/encryptor: truncated cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(contents[off:]))
	off += 2
	if off+csLen > len(contents) {
		return nil, errors.New("ech/encryptor: truncated cipher_suites")
	}
	// Validate at least one suite with our supported algorithms.
	found := false
	for i := 0; i+4 <= csLen; i += 4 {
		kdf := binary.BigEndian.Uint16(contents[off+i:])
		aead := binary.BigEndian.Uint16(contents[off+i+2:])
		if kdf == KDFHKDFSHA256 && aead == AEADAES128GCM {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("ech/encryptor: no supported cipher suite in ECHConfig")
	}
	off += csLen

	// maximum_name_length (1 byte)
	if off >= len(contents) {
		return nil, errors.New("ech/encryptor: truncated maximum_name_length")
	}
	off++ // skip, we don't enforce it

	// public_name (1-byte length prefix)
	if off >= len(contents) {
		return nil, errors.New("ech/encryptor: truncated public_name length")
	}
	nameLen := int(contents[off])
	off++
	if off+nameLen > len(contents) {
		return nil, errors.New("ech/encryptor: truncated public_name")
	}
	publicName := string(contents[off : off+nameLen])

	return &Encryptor{
		config:     echConfig,
		configID:   configID,
		publicKey:  pk,
		publicName: publicName,
	}, nil
}

// PublicName returns the public_name from the ECHConfig.
// This is the SNI that will appear in the outer ClientHello (plaintext).
func (e *Encryptor) PublicName() string {
	return e.publicName
}

// Encrypt takes a plaintext TLS record (containing a ClientHello), encrypts the
// inner CH using HPKE, and returns a new TLS record with an outer ClientHello
// containing the ECH extension.
//
// The inner ClientHello (from the original record) has its SNI preserved.
// The outer ClientHello uses public_name from the ECHConfig as its SNI.
//
// Returns the complete outer TLS record ready to send to the gateway.
func (e *Encryptor) Encrypt(innerRecord []byte) ([]byte, error) {
	if len(innerRecord) < recordHeaderLen+handshakeHeaderLen {
		return nil, errors.New("ech/encryptor: record too short")
	}

	// Extract inner CH body (skip record header + handshake header).
	innerBody := innerRecord[recordHeaderLen+handshakeHeaderLen:]

	// Build the EncodedClientHelloInner:
	// Replace the SNI with ECH inner marker, then compress extensions via
	// ech_outer_extensions. For simplicity in this client implementation,
	// we do NOT use outer_extensions compression — we just pad the inner body.
	padded := padEncodedInner(innerBody, 128)

	// HPKE encrypt.
	enc, ciphertext, err := e.hpkeEncrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("ech/encryptor: HPKE encrypt: %w", err)
	}

	// Build the outer ClientHello record with the ECH extension.
	outerRecord := buildOuterCHRecord(e.publicName, e.configID, enc, ciphertext)

	return outerRecord, nil
}

// EncryptWithSNI is like Encrypt but takes plain inner CH arguments instead of
// a full TLS record. It builds the inner CH from scratch with the given SNI
// and extensions, then wraps in ECH.
//
// This is useful when the client proxy has parsed the original ClientHello and
// wants to re-encrypt with explicit control.
func (e *Encryptor) EncryptWithSNI(innerSNI string, extraExtensions []RawExtension) ([]byte, error) {
	// Build inner CH with the desired SNI.
	exts := []RawExtension{
		{Type: ExtTypeSNI, Data: BuildSNIExtensionData(innerSNI)},
	}
	exts = append(exts, extraExtensions...)
	innerBody := BuildClientHello(innerSNI, exts, nil)

	padded := padEncodedInner(innerBody, 128)

	enc, ciphertext, err := e.hpkeEncrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("ech/encryptor: HPKE encrypt: %w", err)
	}

	return buildOuterCHRecord(e.publicName, e.configID, enc, ciphertext), nil
}

// hpkeEncrypt performs HPKE encryption of the encoded inner CH.
// It constructs the AAD (outer CH body with zero-filled payload) and seals.
func (e *Encryptor) hpkeEncrypt(encodedInner []byte) (enc, ciphertext []byte, err error) {
	pkCircl, err := kemScheme.UnmarshalBinaryPublicKey(e.publicKey.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	// Build HPKE info string: "tls ech\x00" || ECHConfig
	prefix := []byte("tls ech\x00")
	info := make([]byte, len(prefix)+len(e.config))
	copy(info, prefix)
	copy(info[len(prefix):], e.config)

	sender, err := echHPKESuite.NewSender(pkCircl, info)
	if err != nil {
		return nil, nil, fmt.Errorf("create HPKE sender: %w", err)
	}

	enc, sealer, err := sender.Setup(nil) // crypto/rand default
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE setup: %w", err)
	}

	// Compute expected ciphertext length.
	ctLen := len(encodedInner) + 16 // AES-128-GCM tag = 16 bytes

	// Build AAD: outer CH body with zero-filled ECH payload.
	zeroPayload := make([]byte, ctLen)
	aad := buildOuterCHBody(e.publicName, e.configID, enc, zeroPayload)

	ciphertext, err = sealer.Seal(encodedInner, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE seal: %w", err)
	}

	return enc, ciphertext, nil
}
