package ech

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKE cipher suite constants used for ECH (RFC 9180 identifiers).
var echHPKESuite = hpke.NewSuite(
	hpke.KEM_X25519_HKDF_SHA256, // 0x0020
	hpke.KDF_HKDF_SHA256,        // 0x0001
	hpke.AEAD_AES128GCM,         // 0x0001
)

// kemScheme provides key marshaling/unmarshaling for X25519.
var kemScheme = hpke.KEM_X25519_HKDF_SHA256.Scheme()

// Decrypt performs HPKE decryption of an ECH payload and reconstructs
// the inner ClientHello as a complete TLS record.
//
// Steps:
//  1. Look up the key pair by ConfigID (tries Current, then Previous).
//  2. Validate cipher suite parameters (KDF, AEAD).
//  3. Unmarshal the private key for circl's HPKE.
//  4. Set up HPKE receiver with info = "tls ech\x00" || ECHConfig.
//  5. Open (decrypt) the payload using AAD.
//  6. Strip trailing zero padding from EncodedClientHelloInner.
//  7. Expand outer_extensions (0xfd00) if present.
//  8. Extract inner SNI.
//  9. Reconstruct: [record header][handshake header][inner CH body]
//
// Returns the inner SNI and the complete inner ClientHello TLS record.
func (ks *KeySet) Decrypt(result *ParseResult) (string, []byte, error) {
	return ks.DecryptWithPublicName(result, "")
}

// DecryptWithPublicName is like Decrypt but rebuilds the ECHConfig with the
// given publicName for the HPKE info string. This is needed when the ECHConfig
// served via DoH has a per-user public_name (e.g., "<hash>.gw.<domain>") that
// differs from the gateway's default. If publicName is empty, uses the
// KeyPair's existing Config.
func (ks *KeySet) DecryptWithPublicName(result *ParseResult, publicName string) (string, []byte, error) {
	if !result.HasECH {
		return "", nil, errors.New("ech/decrypt: no ECH extension present")
	}

	// --- Step 1: Find matching key pair by config_id ---
	kp := ks.findKeyPair(result.ConfigID)
	if kp == nil {
		return "", nil, fmt.Errorf("ech/decrypt: no key for config_id=%d", result.ConfigID)
	}

	// --- Step 2: Validate cipher suite ---
	if result.KDFID != KDFHKDFSHA256 {
		return "", nil, fmt.Errorf("ech/decrypt: unsupported KDF 0x%04x", result.KDFID)
	}
	if result.AEADID != AEADAES128GCM {
		return "", nil, fmt.Errorf("ech/decrypt: unsupported AEAD 0x%04x", result.AEADID)
	}

	// --- Step 3: Unmarshal private key for circl ---
	skCircl, err := kemScheme.UnmarshalBinaryPrivateKey(kp.PrivateKey())
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: unmarshal private key: %w", err)
	}

	// --- Step 4: Set up HPKE receiver ---
	// If publicName is given, rebuild the ECHConfig with that public_name
	// so the HPKE info string matches the ECHConfig the client used.
	var info []byte
	if publicName != "" {
		tmpKP := &KeyPair{sk: kp.sk, pk: kp.pk, ConfigID: kp.ConfigID}
		BuildECHConfig(tmpKP, publicName)
		info = tmpKP.HPKEInfoString()
	} else {
		info = kp.HPKEInfoString() // "tls ech\x00" || ECHConfig
	}
	receiver, err := echHPKESuite.NewReceiver(skCircl, info)
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: create HPKE receiver: %w", err)
	}

	opener, err := receiver.Setup(result.EncapKey)
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: HPKE setup (bad enc?): %w", err)
	}

	// --- Step 5: Decrypt the ECH payload ---
	// AAD = outer ClientHello with ECH payload region zeroed.
	// Ciphertext = result.ECHPayload.
	encodedInner, err := opener.Open(result.ECHPayload, result.AAD)
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: HPKE open: %w", err)
	}

	// --- Step 6: Strip trailing zero padding ---
	// EncodedClientHelloInner is followed by zero-padding.
	// Per RFC 9849, the inner CH body is guaranteed to not end with 0x00.
	innerCH := stripTrailingZeros(encodedInner)
	if len(innerCH) == 0 {
		return "", nil, errors.New("ech/decrypt: decoded inner CH is empty after stripping padding")
	}

	// --- Step 7: Expand outer_extensions (0xfd00) if present ---
	innerCH, err = expandOuterExtensions(innerCH, result.RawClientHello)
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: expand outer_extensions: %w", err)
	}

	// --- Step 8: Extract inner SNI ---
	innerSNI, err := extractSNIFromBody(innerCH)
	if err != nil {
		return "", nil, fmt.Errorf("ech/decrypt: extract inner SNI: %w", err)
	}

	// --- Step 9: Reconstruct TLS record ---
	// Prepend handshake header (4 bytes) + record header (5 bytes).
	//
	//   Record:    [0x16][0x03 0x03][total_length: 2 bytes]
	//   Handshake: [0x01][body_length: 3 bytes]
	//   Body:      [inner CH body]
	innerCHRecord := WrapInRecord(innerCH)

	return innerSNI, innerCHRecord, nil
}

// SelfTest generates a test key pair, encrypts a synthetic inner ClientHello,
// then parses and decrypts it, verifying the inner SNI survives the round trip.
func (ks *KeySet) SelfTest() error {
	if ks.Current == nil {
		return errors.New("ech/selftest: Current key pair is nil")
	}
	if ks.Current.Config == nil {
		return errors.New("ech/selftest: Current key pair has no ECHConfig (call BuildECHConfig first)")
	}

	const testSNI = "selftest.prism.internal"
	const outerSNI = "probe.gw.prism.dev"

	// Build inner CH.
	innerExts := []RawExtension{
		{Type: ExtTypeSNI, Data: BuildSNIExtensionData(testSNI)},
	}
	innerBody := BuildClientHello(testSNI, innerExts, nil)

	// Pad to at least 128 bytes.
	padded := padEncodedInner(innerBody, 128)

	// Encrypt using HPKE.
	enc, ciphertext, err := hpkeEncrypt(ks.Current, padded, outerSNI)
	if err != nil {
		return fmt.Errorf("ech/selftest: encrypt: %w", err)
	}

	// Build outer CH with ECH extension.
	outerRecord := buildOuterCHRecord(outerSNI, ks.Current.ConfigID, enc, ciphertext)

	// Parse.
	result, err := Parse(outerRecord)
	if err != nil {
		return fmt.Errorf("ech/selftest: parse: %w", err)
	}

	// Decrypt.
	gotSNI, innerRecord, err := ks.Decrypt(result)
	if err != nil {
		return fmt.Errorf("ech/selftest: decrypt: %w", err)
	}

	if gotSNI != testSNI {
		return fmt.Errorf("ech/selftest: SNI mismatch: got %q, want %q", gotSNI, testSNI)
	}
	if len(innerRecord) < recordHeaderLen+handshakeHeaderLen {
		return fmt.Errorf("ech/selftest: inner record too short: %d bytes", len(innerRecord))
	}

	return nil
}

// findKeyPair returns the key pair matching configID, or nil.
func (ks *KeySet) findKeyPair(configID uint8) *KeyPair {
	if ks.Current != nil && ks.Current.ConfigID == configID {
		return ks.Current
	}
	if ks.Previous != nil && ks.Previous.ConfigID == configID {
		return ks.Previous
	}
	return nil
}

// stripTrailingZeros removes trailing 0x00 bytes from b.
// Returns nil if b is all zeros.
func stripTrailingZeros(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0x00 {
		i--
	}
	return b[:i]
}

// expandOuterExtensions processes the inner CH body. If it contains an
// ech_outer_extensions extension (type 0xfd00), it expands it by copying
// the referenced extensions from the outer CH.
//
// The ech_outer_extensions data layout:
//
//	outer_extensions: <2..254>  (1-byte length + list of uint16 types)
//
// Each listed type is looked up in the outer CH and inserted in place
// of the ech_outer_extensions extension itself.
func expandOuterExtensions(innerCH, outerCH []byte) ([]byte, error) {
	innerExts, err := ExtractExtensionsOrdered(innerCH)
	if err != nil {
		return nil, fmt.Errorf("parse inner extensions: %w", err)
	}

	// Check if ech_outer_extensions is present.
	outerExtIdx := -1
	for i, ext := range innerExts {
		if ext.Type == ExtTypeOuterExtensions {
			outerExtIdx = i
			break
		}
	}

	if outerExtIdx == -1 {
		// No outer_extensions — nothing to expand.
		return innerCH, nil
	}

	// Parse the list of extension types to copy from outer CH.
	oeData := innerExts[outerExtIdx].Data
	if len(oeData) < 1 {
		return nil, errors.New("ech_outer_extensions: empty data")
	}
	listLen := int(oeData[0])
	if listLen < 2 || listLen%2 != 0 || 1+listLen > len(oeData) {
		return nil, fmt.Errorf("ech_outer_extensions: invalid list length %d", listLen)
	}

	var typesToCopy []uint16
	for j := 1; j <= listLen; j += 2 {
		typesToCopy = append(typesToCopy, binary.BigEndian.Uint16(oeData[j:j+2]))
	}

	// Extract outer CH extensions.
	outerExtMap, err := ExtractExtensions(outerCH)
	if err != nil {
		return nil, fmt.Errorf("parse outer extensions: %w", err)
	}

	// Build replacement extensions (in order listed by ech_outer_extensions).
	var replacementExts []RawExtension
	for _, extType := range typesToCopy {
		data, ok := outerExtMap[extType]
		if !ok {
			return nil, fmt.Errorf("outer extension 0x%04x not found in outer CH", extType)
		}
		replacementExts = append(replacementExts, RawExtension{Type: extType, Data: data})
	}

	// Rebuild the inner extensions: replace [outerExtIdx] with the expanded set.
	var newExts []RawExtension
	newExts = append(newExts, innerExts[:outerExtIdx]...)
	newExts = append(newExts, replacementExts...)
	newExts = append(newExts, innerExts[outerExtIdx+1:]...)

	// Reconstruct the inner CH body with the new extensions.
	// Reuse the same client_version, random, session_id, cipher_suites, compression.
	return rebuildClientHelloWithExtensions(innerCH, newExts)
}

// rebuildClientHelloWithExtensions replaces the extensions in a ClientHello body
// while preserving all other fields (version, random, session_id, etc.).
func rebuildClientHelloWithExtensions(chBody []byte, newExts []RawExtension) ([]byte, error) {
	// Parse the prefix up to (but not including) the extensions.
	off := 0
	if len(chBody) < 2+32 {
		return nil, errors.New("rebuild: CH body too short")
	}

	// client_version: 2 bytes
	off += 2
	// random: 32 bytes
	off += 32
	// session_id: 1 + len
	if off >= len(chBody) {
		return nil, errors.New("rebuild: truncated at session_id")
	}
	sidLen := int(chBody[off])
	off += 1 + sidLen
	// cipher_suites: 2 + len
	if off+2 > len(chBody) {
		return nil, errors.New("rebuild: truncated at cipher_suites")
	}
	csLen := int(binary.BigEndian.Uint16(chBody[off:]))
	off += 2 + csLen
	// compression_methods: 1 + len
	if off >= len(chBody) {
		return nil, errors.New("rebuild: truncated at compression")
	}
	cmLen := int(chBody[off])
	off += 1 + cmLen

	// Everything before 'off' is the CH prefix (preserved as-is).
	prefix := chBody[:off]

	// Build new extensions block.
	var extBuf []byte
	for _, ext := range newExts {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], ext.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(ext.Data)))
		extBuf = append(extBuf, hdr...)
		extBuf = append(extBuf, ext.Data...)
	}

	// Assemble: prefix + extensions_length(2) + extensions
	result := make([]byte, len(prefix)+2+len(extBuf))
	copy(result, prefix)
	binary.BigEndian.PutUint16(result[len(prefix):], uint16(len(extBuf)))
	copy(result[len(prefix)+2:], extBuf)

	return result, nil
}

// extractSNIFromBody extracts the SNI hostname from a ClientHello body.
func extractSNIFromBody(chBody []byte) (string, error) {
	exts, err := ExtractExtensions(chBody)
	if err != nil {
		return "", err
	}
	sniData, ok := exts[ExtTypeSNI]
	if !ok {
		return "", nil // no SNI extension
	}

	// Parse SNI extension data.
	if len(sniData) < 2 {
		return "", errors.New("SNI extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(sniData[0:2]))
	if 2+listLen > len(sniData) {
		return "", errors.New("SNI list length overflow")
	}

	off := 2
	end := 2 + listLen
	for off < end {
		if off+3 > end {
			return "", errors.New("SNI entry truncated")
		}
		nameType := sniData[off]
		nameLen := int(binary.BigEndian.Uint16(sniData[off+1 : off+3]))
		off += 3
		if off+nameLen > end {
			return "", errors.New("SNI name truncated")
		}
		if nameType == 0x00 { // hostname
			return string(sniData[off : off+nameLen]), nil
		}
		off += nameLen
	}
	return "", nil
}

// --- Encryption helpers (used by SelfTest and tests) ---

// hpkeEncrypt encrypts the encoded inner CH using HPKE for the given key pair.
// It constructs the outer CH with a zero-filled placeholder for the payload
// to compute the correct AAD, then performs HPKE Seal.
//
// Returns: enc (encapsulated key), ciphertext.
func hpkeEncrypt(kp *KeyPair, encodedInner []byte, outerSNI string) ([]byte, []byte, error) {
	pkCircl, err := kemScheme.UnmarshalBinaryPublicKey(kp.PublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	info := kp.HPKEInfoString()
	sender, err := echHPKESuite.NewSender(pkCircl, info)
	if err != nil {
		return nil, nil, fmt.Errorf("create HPKE sender: %w", err)
	}

	enc, sealer, err := sender.Setup(nil) // nil = crypto/rand default
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE setup: %w", err)
	}

	// The ciphertext length = plaintext + AEAD tag (16 bytes for AES-128-GCM).
	// Construct the AAD: an outer CH with a zero-filled payload of the expected
	// ciphertext length.
	ctLen := len(encodedInner) + 16 // AES-128-GCM tag overhead
	zeroPayload := make([]byte, ctLen)
	aad := buildOuterCHBody(outerSNI, kp.ConfigID, enc, zeroPayload)

	ciphertext, err := sealer.Seal(encodedInner, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE seal: %w", err)
	}

	return enc, ciphertext, nil
}

// buildOuterCHBody constructs an outer ClientHello body (no record/handshake headers)
// with SNI and ECH extensions.
func buildOuterCHBody(outerSNI string, configID uint8, enc, payload []byte) []byte {
	echData := buildECHExtData(configID, enc, payload)
	exts := []RawExtension{
		{Type: ExtTypeSNI, Data: BuildSNIExtensionData(outerSNI)},
		{Type: ExtTypeECH, Data: echData},
	}
	return BuildClientHello(outerSNI, exts, nil)
}

// buildOuterCHRecord wraps buildOuterCHBody in TLS record + handshake headers.
func buildOuterCHRecord(outerSNI string, configID uint8, enc, payload []byte) []byte {
	chBody := buildOuterCHBody(outerSNI, configID, enc, payload)
	return WrapInRecord(chBody)
}

// buildECHExtData builds the ECH outer extension data bytes.
//
// Layout:
//
//	[0]       type = 0x00 (outer)
//	[1:3]     kdf_id = 0x0001
//	[3:5]     aead_id = 0x0001
//	[5]       config_id
//	[6:8]     enc_len
//	[8:8+N]   enc
//	[8+N:10+N] payload_len
//	[10+N:]   payload
func buildECHExtData(configID uint8, enc, payload []byte) []byte {
	size := 1 + 2 + 2 + 1 + 2 + len(enc) + 2 + len(payload)
	buf := make([]byte, size)
	off := 0

	buf[off] = ECHTypeOuter
	off++
	binary.BigEndian.PutUint16(buf[off:], KDFHKDFSHA256)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], AEADAES128GCM)
	off += 2
	buf[off] = configID
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(len(enc)))
	off += 2
	copy(buf[off:], enc)
	off += len(enc)
	binary.BigEndian.PutUint16(buf[off:], uint16(len(payload)))
	off += 2
	copy(buf[off:], payload)

	return buf
}

// padEncodedInner appends zero bytes to the encoded inner CH body
// so that its total length is at least minLen.
func padEncodedInner(body []byte, minLen int) []byte {
	if len(body) >= minLen {
		// Still add at least 1 byte of padding to ensure non-ambiguity.
		return append(body, 0x00)
	}
	padLen := minLen - len(body)
	return append(body, make([]byte, padLen)...)
}

// circl kem.PrivateKey / kem.PublicKey are interface types.
// Ensure our usage is correct at compile time.
var _ kem.PrivateKey = (*struct{ kem.PrivateKey })(nil)
