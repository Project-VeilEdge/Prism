// Package ech implements ECH (Encrypted Client Hello) parsing and decryption.
// All operations are pure byte manipulation — zero network I/O.
package ech

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// TLS extension type constants.
const (
	ExtTypeSNI             uint16 = 0x0000 // Server Name Indication
	ExtTypeECH             uint16 = 0xfe0d // Encrypted Client Hello (RFC 9849)
	ExtTypeOuterExtensions uint16 = 0xfd00 // ECH outer_extensions (inner CH)
)

// ECH ClientHello type bytes.
const (
	ECHTypeOuter byte = 0x00
	ECHTypeInner byte = 0x01
)

// TLS constants.
const (
	recordHeaderLen               = 5 // [content_type(1)][version(2)][length(2)]
	handshakeHeaderLen            = 4 // [msg_type(1)][length(3)]
	handshakeTypeClientHello byte = 0x01
)

// ParseResult holds the parsed ClientHello fields needed for ECH decryption.
type ParseResult struct {
	HasECH         bool   // true if ECH extension (0xfe0d, outer type) was found
	RawRecord      []byte // full TLS record as received (header + payload)
	RawClientHello []byte // ClientHello body: starts at client_version (record[9:])
	OuterSNI       string // SNI from the outer ClientHello (plaintext)
	ECHPayload     []byte // encrypted inner CH ciphertext
	EncapKey       []byte // HPKE encapsulated key (enc)
	ConfigID       uint8  // ECH config_id
	KDFID          uint16 // HPKE KDF identifier
	AEADID         uint16 // HPKE AEAD identifier
	AAD            []byte // AAD = RawClientHello with ECH payload zeroed

	// Internal: byte range of ECH payload within RawClientHello for AAD construction.
	echPayloadStart int // offset of payload bytes within RawClientHello
	echPayloadEnd   int // end offset (exclusive) within RawClientHello
}

// Parse dissects a raw TLS record containing a ClientHello message.
// It extracts the outer SNI, detects and parses the ECH extension (type 0xfe0d),
// and constructs the AAD needed for HPKE decryption.
//
// All parsing uses golang.org/x/crypto/cryptobyte — NO string ops or regex on wire bytes.
//
// Record layout:
//
//	Offset  Field
//	[0]     content_type    = 0x16 (Handshake)
//	[1:3]   version         = 0x0301 or 0x0303
//	[3:5]   record_length   (big-endian uint16)
//	[5]     msg_type        = 0x01 (ClientHello)
//	[6:9]   handshake_length (uint24)
//	[9:]    ClientHello body: version(2) + random(32) + session_id + cipher_suites + compression + extensions
func Parse(record []byte) (*ParseResult, error) {
	result := &ParseResult{
		RawRecord: record,
	}

	// --- Step 1: Parse TLS Record Header ---
	s := cryptobyte.String(record)

	var contentType uint8
	var recordVersion uint16
	var recordPayload cryptobyte.String
	if !s.ReadUint8(&contentType) ||
		!s.ReadUint16(&recordVersion) ||
		!s.ReadUint16LengthPrefixed(&recordPayload) {
		return nil, errors.New("ech/parse: invalid TLS record header")
	}
	if contentType != 0x16 { // must be Handshake
		return nil, fmt.Errorf("ech/parse: not a handshake record (type=0x%02x)", contentType)
	}

	// --- Step 2: Parse Handshake Header ---
	var msgType uint8
	var hsBody cryptobyte.String
	if !recordPayload.ReadUint8(&msgType) ||
		!recordPayload.ReadUint24LengthPrefixed(&hsBody) {
		return nil, errors.New("ech/parse: invalid handshake header")
	}
	if msgType != handshakeTypeClientHello {
		return nil, fmt.Errorf("ech/parse: not ClientHello (msg_type=0x%02x)", msgType)
	}

	// RawClientHello = the ClientHello body (starts at client_version).
	// It begins at record offset 9 (5 record header + 4 handshake header).
	chLen := len(hsBody)
	result.RawClientHello = record[recordHeaderLen+handshakeHeaderLen : recordHeaderLen+handshakeHeaderLen+chLen]

	// --- Step 3: Parse ClientHello Fields ---
	// Fields parsed in order per RFC 8446 §4.1.2:
	//   client_version(2) + random(32) + session_id(var) + cipher_suites(var) + compression(var) + extensions(var)

	var clientVersion uint16
	var random []byte
	var sessionID, cipherSuites, compressionMethods cryptobyte.String

	if !hsBody.ReadUint16(&clientVersion) { // [0:2] legacy_version
		return nil, errors.New("ech/parse: truncated client_version")
	}
	if !hsBody.ReadBytes(&random, 32) { // [2:34] random
		return nil, errors.New("ech/parse: truncated random")
	}
	if !hsBody.ReadUint8LengthPrefixed(&sessionID) { // session_id<0..32>
		return nil, errors.New("ech/parse: truncated session_id")
	}
	if !hsBody.ReadUint16LengthPrefixed(&cipherSuites) { // cipher_suites<2..2^16-2>
		return nil, errors.New("ech/parse: truncated cipher_suites")
	}
	if !hsBody.ReadUint8LengthPrefixed(&compressionMethods) { // compression_methods<1..2^8-1>
		return nil, errors.New("ech/parse: truncated compression_methods")
	}

	// Compute the byte offset where extensions data starts within RawClientHello.
	// Layout so far: version(2) + random(32) + sid_len(1) + sid(N) + cs_len(2) + cs(N) + cm_len(1) + cm(N) + ext_len(2)
	extDataOffset := 2 + 32 + 1 + len(sessionID) + 2 + len(cipherSuites) + 1 + len(compressionMethods) + 2

	// --- Step 4: Parse Extensions ---
	var extensions cryptobyte.String
	if !hsBody.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("ech/parse: truncated extensions")
	}

	// Track byte position within the extensions block.
	extBlockLen := len(extensions)

	for !extensions.Empty() {
		// Record position in extensions block BEFORE reading this extension.
		posInExtBlock := extBlockLen - len(extensions)

		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("ech/parse: malformed extension")
		}

		switch extType {
		case ExtTypeSNI:
			sni, err := parseSNI(extData)
			if err != nil {
				return nil, fmt.Errorf("ech/parse: %w", err)
			}
			result.OuterSNI = sni

		case ExtTypeECH:
			if err := parseECHExtension(result, extData, extDataOffset, posInExtBlock); err != nil {
				return nil, fmt.Errorf("ech/parse: %w", err)
			}
		}
	}

	// --- Step 5: Construct AAD ---
	if result.HasECH {
		result.AAD = buildAAD(result.RawClientHello, result.echPayloadStart, result.echPayloadEnd)
	}

	return result, nil
}

// parseSNI extracts the hostname from an SNI extension.
//
// SNI extension data layout:
//
//	server_name_list: <2..2^16-1>  (uint16 length-prefixed list)
//	  name_type:    uint8          (0x00 = hostname)
//	  host_name:    <1..2^16-1>    (uint16 length-prefixed)
func parseSNI(data cryptobyte.String) (string, error) {
	var nameList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&nameList) {
		return "", errors.New("invalid SNI name list")
	}

	for !nameList.Empty() {
		var nameType uint8
		var nameData cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&nameData) {
			return "", errors.New("invalid SNI entry")
		}
		if nameType == 0x00 { // hostname
			return string(nameData), nil
		}
	}
	return "", nil
}

// parseECHExtension parses the ECH extension data (type 0xfe0d).
//
// ECH outer extension layout (RFC 9849 §5):
//
//	Offset  Field
//	[0]     type:         uint8  (0x00=outer, 0x01=inner)
//	[1:3]   kdf_id:       uint16
//	[3:5]   aead_id:      uint16
//	[5]     config_id:    uint8
//	[6:8]   enc_len:      uint16
//	[8:8+N] enc:          N bytes (HPKE encapsulated key)
//	[...]   payload_len:  uint16
//	[...]   payload:      M bytes (encrypted inner CH)
//
// Parameters:
//   - extDataOffset: byte offset where extensions data starts within RawClientHello
//   - posInExtBlock: byte offset of this extension within the extensions block
func parseECHExtension(result *ParseResult, data cryptobyte.String, extDataOffset, posInExtBlock int) error {
	var echType uint8
	if !data.ReadUint8(&echType) {
		return errors.New("ECH extension: truncated type")
	}

	if echType == ECHTypeInner {
		// Inner type marker — nothing to extract.
		return nil
	}
	if echType != ECHTypeOuter {
		return fmt.Errorf("ECH extension: unknown type 0x%02x", echType)
	}

	// Parse outer ECH fields.
	var kdfID, aeadID uint16
	var configID uint8
	var enc, payload cryptobyte.String

	if !data.ReadUint16(&kdfID) || // [1:3]  kdf_id
		!data.ReadUint16(&aeadID) || // [3:5]  aead_id
		!data.ReadUint8(&configID) || // [5]    config_id
		!data.ReadUint16LengthPrefixed(&enc) || // [6:8+N] enc
		!data.ReadUint16LengthPrefixed(&payload) { // payload
		return errors.New("ECH extension: truncated fields")
	}

	result.HasECH = true
	result.ConfigID = configID
	result.KDFID = kdfID
	result.AEADID = aeadID
	result.EncapKey = []byte(enc)
	result.ECHPayload = []byte(payload)

	// --- Compute payload byte range within RawClientHello ---
	//
	// The extension in the extensions block is at offset posInExtBlock:
	//   ext_type(2) + ext_data_len(2) + ext_data(...)
	//
	// Within ext_data, the payload starts after:
	//   type(1) + kdf_id(2) + aead_id(2) + config_id(1) + enc_len(2) + enc(N) + payload_len(2)
	//   = 8 + len(enc) + 2 = 10 + len(enc)
	//
	// Absolute offset in RawClientHello:
	//   extDataOffset + posInExtBlock + 4 (ext header) + payloadOffsetInExtData

	payloadOffsetInExtData := 1 + 2 + 2 + 1 + 2 + len(enc) + 2 // = 10 + len(enc)
	absStart := extDataOffset + posInExtBlock + 4 + payloadOffsetInExtData
	absEnd := absStart + len(payload)

	result.echPayloadStart = absStart
	result.echPayloadEnd = absEnd

	return nil
}

// buildAAD constructs the Additional Authenticated Data for HPKE decryption.
// It copies the entire RawClientHello and replaces the ECH payload region
// (bytes [start:end]) with zeros of equal length.
//
// The extension type, length fields, and all other bytes remain untouched.
// This ensures len(AAD) == len(RawClientHello).
func buildAAD(rawCH []byte, payloadStart, payloadEnd int) []byte {
	aad := make([]byte, len(rawCH))
	copy(aad, rawCH)
	// Zero out exactly the payload bytes.
	for i := payloadStart; i < payloadEnd; i++ {
		aad[i] = 0x00
	}
	return aad
}

// ExtractExtensions parses all extensions from a ClientHello body and returns
// them as a map of type -> raw extension data (without type and length prefix).
// Used by the decryptor for outer_extensions expansion.
func ExtractExtensions(chBody []byte) (map[uint16][]byte, error) {
	s := cryptobyte.String(chBody)

	// Skip: client_version(2) + random(32) + session_id(var) + cipher_suites(var) + compression(var)
	var skip16 uint16
	var skipBytes []byte
	var skipVar cryptobyte.String
	if !s.ReadUint16(&skip16) || // client_version
		!s.ReadBytes(&skipBytes, 32) || // random
		!s.ReadUint8LengthPrefixed(&skipVar) || // session_id
		!s.ReadUint16LengthPrefixed(&skipVar) || // cipher_suites
		!s.ReadUint8LengthPrefixed(&skipVar) { // compression
		return nil, errors.New("ech/extractExtensions: truncated ClientHello")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("ech/extractExtensions: truncated extensions")
	}

	result := make(map[uint16][]byte)
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("ech/extractExtensions: malformed extension")
		}
		result[extType] = []byte(extData)
	}
	return result, nil
}

// ExtractExtensionsOrdered returns extensions from a ClientHello body as
// an ordered slice preserving the original order. Each element has the raw
// extension bytes (type + length + data).
func ExtractExtensionsOrdered(chBody []byte) ([]RawExtension, error) {
	s := cryptobyte.String(chBody)

	var skip16 uint16
	var skipBytes []byte
	var skipVar cryptobyte.String
	if !s.ReadUint16(&skip16) ||
		!s.ReadBytes(&skipBytes, 32) ||
		!s.ReadUint8LengthPrefixed(&skipVar) ||
		!s.ReadUint16LengthPrefixed(&skipVar) ||
		!s.ReadUint8LengthPrefixed(&skipVar) {
		return nil, errors.New("ech/extractExtensionsOrdered: truncated ClientHello")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("ech/extractExtensionsOrdered: truncated extensions")
	}

	var result []RawExtension
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("ech/extractExtensionsOrdered: malformed extension")
		}
		result = append(result, RawExtension{Type: extType, Data: []byte(extData)})
	}
	return result, nil
}

// RawExtension holds a parsed but uninterpreted TLS extension.
type RawExtension struct {
	Type uint16
	Data []byte // extension data without the type(2) + length(2) header
}

// BuildClientHello constructs a minimal ClientHello body from components.
// Used by tests and the decryptor for inner CH reconstruction.
//
// The returned bytes start at client_version (no record/handshake headers).
func BuildClientHello(sni string, extensions []RawExtension, sessionID []byte) []byte {
	// Pre-compute extensions block.
	var extBuf []byte
	for _, ext := range extensions {
		// Each extension: type(2) + length(2) + data
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], ext.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(ext.Data)))
		extBuf = append(extBuf, hdr...)
		extBuf = append(extBuf, ext.Data...)
	}

	// Build the ClientHello body.
	var ch []byte

	// client_version: TLS 1.2 (0x0303)
	ch = append(ch, 0x03, 0x03)

	// random: 32 zero bytes (test-friendly)
	ch = append(ch, make([]byte, 32)...)

	// session_id
	if sessionID == nil {
		sessionID = []byte{}
	}
	ch = append(ch, byte(len(sessionID)))
	ch = append(ch, sessionID...)

	// cipher_suites: TLS_AES_128_GCM_SHA256 (0x1301)
	ch = append(ch, 0x00, 0x02, 0x13, 0x01)

	// compression_methods: null
	ch = append(ch, 0x01, 0x00)

	// extensions
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extBuf)))
	ch = append(ch, extLen...)
	ch = append(ch, extBuf...)

	return ch
}

// BuildSNIExtensionData builds the SNI extension data for a given hostname.
//
//	server_name_list_length(2) + name_type(1) + name_length(2) + name(N)
func BuildSNIExtensionData(hostname string) []byte {
	nameLen := len(hostname)
	// list length = name_type(1) + name_length(2) + name(N) = 3 + N
	listLen := 1 + 2 + nameLen
	buf := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(listLen))
	buf[2] = 0x00 // name_type = hostname
	binary.BigEndian.PutUint16(buf[3:5], uint16(nameLen))
	copy(buf[5:], hostname)
	return buf
}

// WrapInRecord wraps a ClientHello body in TLS record + handshake headers.
//
// Output layout:
//
//	[0]       0x16         (content_type = Handshake)
//	[1:3]     0x0303       (TLS 1.2)
//	[3:5]     total_len    (handshake header + CH body)
//	[5]       0x01         (msg_type = ClientHello)
//	[6:9]     ch_len       (uint24, length of CH body)
//	[9:]      CH body
func WrapInRecord(chBody []byte) []byte {
	chLen := len(chBody)
	totalPayload := handshakeHeaderLen + chLen // 4 + chLen
	record := make([]byte, recordHeaderLen+totalPayload)

	// Record header
	record[0] = 0x16 // Handshake
	record[1] = 0x03
	record[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(record[3:5], uint16(totalPayload))

	// Handshake header
	record[5] = handshakeTypeClientHello // 0x01
	// uint24 length (3 bytes, big-endian)
	record[6] = byte(chLen >> 16)
	record[7] = byte(chLen >> 8)
	record[8] = byte(chLen)

	// CH body
	copy(record[9:], chBody)
	return record
}
