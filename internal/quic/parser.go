// Package quic implements QUIC Initial packet parsing for extracting TLS ClientHello.
// It handles header protection removal, HKDF-based key derivation, and AES-128-GCM
// payload decryption per RFC 9001 (QUIC-TLS) and RFC 9000 (QUIC Transport).
//
// This package performs pure byte-level operations — no QUIC connection state or
// transport management. It exists solely to extract the TLS ClientHello from the
// first flight of a QUIC handshake for ECH-aware routing.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// QUIC version 1 (RFC 9000) initial salt for key derivation.
// RFC 9001 §5.2: "The hash function for HKDF when deriving initial secrets and
// keys is SHA-256."
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// QUIC version 2 (RFC 9369) initial salt.
var quicV2InitialSalt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
}

// Supported QUIC versions.
const (
	QUICVersion1 uint32 = 0x00000001 // RFC 9000
	QUICVersion2 uint32 = 0x6b3343cf // RFC 9369
)

// QUIC packet type for Long Header (top 2 bits of first byte after the form bit).
const (
	packetTypeInitial   = 0x00
	packetTypeV2Initial = 0x01 // In QUIC v2, Initial uses type bits 0b01
)

// MaxConnectionIDLen is the maximum connection ID length per RFC 9000 §17.2.
const MaxConnectionIDLen = 20

// Sentinel errors for callers to distinguish specific failure modes.
var (
	// ErrNotInitialPacket indicates the packet is a valid QUIC long header but
	// not an Initial packet (e.g., Handshake, 0-RTT, Retry).
	ErrNotInitialPacket = errors.New("quic: not an Initial packet")

	// ErrIncompleteClientHello indicates the CRYPTO data in this single Initial
	// packet does not contain the full TLS ClientHello message. The declared
	// handshake length exceeds the available CRYPTO data, meaning the ClientHello
	// is split across multiple Initial packets.
	ErrIncompleteClientHello = errors.New("quic: ClientHello spans multiple Initial packets")
)

// ParsedInitial holds the result of parsing a QUIC Initial packet.
type ParsedInitial struct {
	Version     uint32 // QUIC version from the header
	DCID        []byte // Destination Connection ID
	SCID        []byte // Source Connection ID
	TokenLen    int    // Token length (may be non-zero for Retry)
	Token       []byte // Token bytes
	PacketNum   uint32 // Decoded packet number
	Payload     []byte // Decrypted payload (QUIC frames)
	CryptoData  []byte // Reassembled CRYPTO frame data (TLS ClientHello message)
	ClientHello []byte // TLS ClientHello bytes extracted from crypto data (starting at handshake type 0x01)
}

// ParseInitial parses a QUIC Initial packet from a UDP datagram payload.
// It removes header protection, decrypts the packet payload, extracts
// CRYPTO frames, and returns the contained TLS ClientHello.
//
// The returned ParsedInitial.ClientHello contains the full TLS Handshake
// message (type + length + body) suitable for wrapping in a TLS record and
// feeding to ech.Parse.
func ParseInitial(data []byte) (*ParsedInitial, error) {
	if len(data) < 5 {
		return nil, errors.New("quic: packet too short")
	}

	// Check Long Header form bit (bit 7 of first byte must be 1).
	if data[0]&0x80 == 0 {
		return nil, errors.New("quic: not a long header packet")
	}

	// Fixed bit (bit 6) should be 1 for QUIC v1.
	// We don't enforce this strictly as some versions may differ.

	// Extract version.
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		return nil, errors.New("quic: version negotiation packet, not Initial")
	}

	// Verify this is an Initial packet type.
	if !isInitialPacket(data[0], version) {
		return nil, ErrNotInitialPacket
	}

	// Select initial salt based on version.
	salt := initialSaltForVersion(version)
	if salt == nil {
		return nil, fmt.Errorf("quic: unsupported version 0x%08x", version)
	}

	// Parse remainder of long header.
	offset := 5

	// DCID length (1 byte) + DCID.
	if offset >= len(data) {
		return nil, errors.New("quic: truncated DCID length")
	}
	dcidLen := int(data[offset])
	offset++
	if dcidLen > MaxConnectionIDLen {
		return nil, fmt.Errorf("quic: DCID length %d exceeds maximum %d", dcidLen, MaxConnectionIDLen)
	}
	if offset+dcidLen > len(data) {
		return nil, errors.New("quic: truncated DCID")
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, data[offset:offset+dcidLen])
	offset += dcidLen

	// SCID length (1 byte) + SCID.
	if offset >= len(data) {
		return nil, errors.New("quic: truncated SCID length")
	}
	scidLen := int(data[offset])
	offset++
	if scidLen > MaxConnectionIDLen {
		return nil, fmt.Errorf("quic: SCID length %d exceeds maximum %d", scidLen, MaxConnectionIDLen)
	}
	if offset+scidLen > len(data) {
		return nil, errors.New("quic: truncated SCID")
	}
	scid := make([]byte, scidLen)
	copy(scid, data[offset:offset+scidLen])
	offset += scidLen

	// Token length (variable-length integer) + Token.
	tokenLen, n, err := readVarInt(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("quic: token length: %w", err)
	}
	offset += n
	if offset+int(tokenLen) > len(data) {
		return nil, errors.New("quic: truncated token")
	}
	token := data[offset : offset+int(tokenLen)]
	offset += int(tokenLen)

	// Payload length (variable-length integer).
	payloadLen, n, err := readVarInt(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("quic: payload length: %w", err)
	}
	offset += n

	// The "payload" here includes the packet number + encrypted payload.
	// Verify we have enough data.
	if offset+int(payloadLen) > len(data) {
		return nil, fmt.Errorf("quic: payload truncated: need %d, have %d",
			payloadLen, len(data)-offset)
	}

	// headerOffset is where we ended parsing the unprotected portion of the header.
	// The packet number starts here but is encrypted.
	pnOffset := offset

	// --- Key Derivation (RFC 9001 §5.2) ---
	clientKey, clientIV, clientHP, err := deriveInitialKeys(dcid, salt)
	if err != nil {
		return nil, fmt.Errorf("quic: derive keys: %w", err)
	}

	// --- Remove Header Protection (RFC 9001 §5.4.3) ---
	// Sample starts 4 bytes after the start of the Packet Number field.
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > offset+int(payloadLen) {
		return nil, errors.New("quic: not enough data for HP sample")
	}
	sample := data[sampleOffset : sampleOffset+16]

	// Create AES-ECB cipher for HP removal.
	hpBlock, err := aes.NewCipher(clientHP)
	if err != nil {
		return nil, fmt.Errorf("quic: HP cipher: %w", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, sample)

	// Remove protection from first byte.
	// For long headers, the lower 4 bits of the first byte are protected.
	data[0] ^= mask[0] & 0x0f

	// Determine packet number length from the now-unprotected first byte.
	pnLen := int(data[0]&0x03) + 1

	// Remove protection from the packet number bytes.
	for i := 0; i < pnLen; i++ {
		data[pnOffset+i] ^= mask[1+i]
	}

	// Decode packet number.
	var pn uint32
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint32(data[pnOffset+i])
	}

	// --- Construct nonce and decrypt (RFC 9001 §5.3) ---
	nonce := make([]byte, len(clientIV))
	copy(nonce, clientIV)
	// XOR the packet number into the last bytes of the IV.
	for i := 0; i < pnLen; i++ {
		nonce[len(nonce)-pnLen+i] ^= data[pnOffset+i]
	}

	// The AEAD-protected payload starts after the packet number.
	ciphertext := data[pnOffset+pnLen : offset+int(payloadLen)]

	// AAD is the entire header up to and including the packet number.
	aad := data[:pnOffset+pnLen]

	// Decrypt with AES-128-GCM.
	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, fmt.Errorf("quic: AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("quic: AES-GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("quic: AEAD decrypt failed: %w", err)
	}

	// --- Extract CRYPTO frames (RFC 9000 §19.6) ---
	cryptoData, err := extractCryptoFrames(plaintext)
	if err != nil {
		return nil, fmt.Errorf("quic: %w", err)
	}

	// The CRYPTO data should contain a TLS Handshake message (ClientHello).
	// TLS Handshake: msg_type(1) + length(3) + body
	var clientHello []byte
	if len(cryptoData) >= 4 && cryptoData[0] == 0x01 { // ClientHello
		hsLen := int(cryptoData[1])<<16 | int(cryptoData[2])<<8 | int(cryptoData[3])
		needed := 4 + hsLen
		if needed > len(cryptoData) {
			// The ClientHello is split across multiple Initial packets.
			// We have only a fragment; caller must buffer and reassemble.
			return nil, ErrIncompleteClientHello
		}
		clientHello = cryptoData[:needed]
	}

	return &ParsedInitial{
		Version:     version,
		DCID:        dcid,
		SCID:        scid,
		TokenLen:    int(tokenLen),
		Token:       token,
		PacketNum:   pn,
		Payload:     plaintext,
		CryptoData:  cryptoData,
		ClientHello: clientHello,
	}, nil
}

// WrapClientHelloRecord wraps a TLS Handshake message (e.g., ClientHello from
// CRYPTO frames) in a TLS record suitable for ech.Parse.
//
// Output: [0x16][0x0303][length:2][handshake message]
func WrapClientHelloRecord(handshakeMsg []byte) []byte {
	totalLen := len(handshakeMsg)
	record := make([]byte, 5+totalLen)
	record[0] = 0x16 // Handshake
	record[1] = 0x03
	record[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(record[3:5], uint16(totalLen))
	copy(record[5:], handshakeMsg)
	return record
}

// isInitialPacket tests whether the first byte indicates an Initial packet
// for the given QUIC version.
func isInitialPacket(firstByte byte, version uint32) bool {
	// Long Header packet type is in bits 4-5 of the first byte (before HP removal).
	// But header protection masks the lower 4 bits only, not bits 4-5.
	// So we can read the packet type from the unprotected bits.
	typeBits := (firstByte & 0x30) >> 4
	switch version {
	case QUICVersion1:
		return typeBits == packetTypeInitial // 0x00
	case QUICVersion2:
		return typeBits == packetTypeV2Initial // 0x01
	default:
		// Assume v1-style for unknown versions.
		return typeBits == packetTypeInitial
	}
}

// initialSaltForVersion returns the HKDF initial salt for the given QUIC version.
func initialSaltForVersion(version uint32) []byte {
	switch version {
	case QUICVersion1:
		return quicV1InitialSalt
	case QUICVersion2:
		return quicV2InitialSalt
	default:
		// Try v1 salt for draft versions in the 0xff000000 range.
		if version&0xff000000 == 0xff000000 {
			return quicV1InitialSalt
		}
		return nil
	}
}

// deriveInitialKeys derives the client Initial keys from the Destination Connection ID.
//
// Per RFC 9001 §5.2:
//  1. initial_secret = HKDF-Extract(salt, DCID)
//  2. client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//  3. key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
//  4. iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
//  5. hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
func deriveInitialKeys(dcid, salt []byte) (key, iv, hp []byte, err error) {
	// Step 1: Extract initial secret.
	h := hkdf.Extract(sha256.New, dcid, salt)

	// Step 2: client_initial_secret.
	clientSecret, err := hkdfExpandLabel(h, "client in", nil, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("client secret: %w", err)
	}

	// Step 3-5: Derive key, IV, HP key.
	key, err = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key: %w", err)
	}

	iv, err = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("iv: %w", err)
	}

	hp, err = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hp: %w", err)
	}

	return key, iv, hp, nil
}

// hkdfExpandLabel derives a key using TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
//
// HKDF-Expand-Label uses the label prefix "tls13 " per the TLS 1.3 spec,
// which QUIC inherits.
//
//	struct {
//	    uint16 length;
//	    opaque label<7..255>;       // "tls13 " + label
//	    opaque context<0..255>;
//	} HkdfLabel;
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	r := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readVarInt reads a QUIC variable-length integer (RFC 9000 §16).
// Returns the value, bytes consumed, and any error.
func readVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data for varint")
	}

	// The two most significant bits encode the length.
	prefix := data[0] >> 6
	length := 1 << prefix // 1, 2, 4, or 8 bytes

	if len(data) < length {
		return 0, 0, fmt.Errorf("varint: need %d bytes, have %d", length, len(data))
	}

	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3f)
	case 2:
		val = uint64(binary.BigEndian.Uint16(data[:2])) & 0x3fff
	case 4:
		val = uint64(binary.BigEndian.Uint32(data[:4])) & 0x3fffffff
	case 8:
		val = binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff
	}

	return val, length, nil
}

// extractCryptoFrames scans decrypted QUIC frames for CRYPTO frames (type 0x06)
// and reassembles them. It also handles PADDING frames (0x00) and ACK frames (0x02/0x03).
// Other frame types are skipped.
func extractCryptoFrames(payload []byte) ([]byte, error) {
	// We use a simple approach: collect CRYPTO frame data keyed by offset,
	// then reassemble in order. For the Initial packet containing a ClientHello,
	// there is typically a single CRYPTO frame starting at offset 0.
	type fragment struct {
		offset uint64
		data   []byte
	}
	var fragments []fragment

	pos := 0
	for pos < len(payload) {
		frameType := payload[pos]

		switch {
		case frameType == 0x00:
			// PADDING — skip single zero byte.
			pos++

		case frameType == 0x02 || frameType == 0x03:
			// ACK frame (0x02) or ACK_ECN frame (0x03) — skip it.
			isECN := frameType == 0x03
			pos++
			n, err := skipACKFrame(payload[pos:], isECN)
			if err != nil {
				return nil, fmt.Errorf("ACK frame: %w", err)
			}
			pos += n

		case frameType == 0x06:
			// CRYPTO frame: type(1) + offset(varint) + length(varint) + data
			pos++ // skip frame type

			cryptoOffset, n, err := readVarInt(payload[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO offset: %w", err)
			}
			pos += n

			cryptoLen, n, err := readVarInt(payload[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO length: %w", err)
			}
			pos += n

			if pos+int(cryptoLen) > len(payload) {
				return nil, fmt.Errorf("CRYPTO data truncated: need %d, have %d",
					cryptoLen, len(payload)-pos)
			}

			frag := make([]byte, cryptoLen)
			copy(frag, payload[pos:pos+int(cryptoLen)])
			fragments = append(fragments, fragment{offset: cryptoOffset, data: frag})
			pos += int(cryptoLen)

		case frameType == 0x1c:
			// CONNECTION_CLOSE frame — stop processing.
			return nil, errors.New("CONNECTION_CLOSE in Initial")

		default:
			// Unknown frame type — try to read as varint-typed frame.
			// For the Initial encryption level, the only allowed frames are
			// PADDING, ACK, CRYPTO, CONNECTION_CLOSE, and PING (0x01).
			if frameType == 0x01 {
				pos++ // PING — no payload
				continue
			}
			// For safety, stop parsing on unknown frames.
			goto done
		}
	}

done:
	if len(fragments) == 0 {
		return nil, errors.New("no CRYPTO frames found")
	}

	// Reassemble: sort by offset and concatenate.
	// Most Initial packets have a single fragment at offset 0.
	// For simplicity and correctness, handle gaps/overlaps.
	var maxEnd uint64
	for _, f := range fragments {
		end := f.offset + uint64(len(f.data))
		if end > maxEnd {
			maxEnd = end
		}
	}

	result := make([]byte, maxEnd)
	for _, f := range fragments {
		copy(result[f.offset:], f.data)
	}

	return result, nil
}

// skipACKFrame skips an ACK frame body (after the type byte has been consumed).
// If isECN is true, the three additional ECN count fields (ECT(0), ECT(1), CE)
// are also consumed per RFC 9000 §19.3.2.
// Returns the number of bytes consumed.
func skipACKFrame(data []byte, isECN bool) (int, error) {
	pos := 0

	// Largest Acknowledged (varint)
	_, n, err := readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	// ACK Delay (varint)
	_, n, err = readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	// ACK Range Count (varint)
	rangeCount, n, err := readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	// First ACK Range (varint)
	_, n, err = readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	// Additional ACK Ranges
	for i := uint64(0); i < rangeCount; i++ {
		// Gap (varint)
		_, n, err = readVarInt(data[pos:])
		if err != nil {
			return 0, err
		}
		pos += n

		// ACK Range Length (varint)
		_, n, err = readVarInt(data[pos:])
		if err != nil {
			return 0, err
		}
		pos += n
	}

	// ACK_ECN (0x03) has three additional varint fields: ECT(0), ECT(1), CE Count.
	if isECN {
		for i := 0; i < 3; i++ {
			_, n, err = readVarInt(data[pos:])
			if err != nil {
				return 0, fmt.Errorf("ECN count field %d: %w", i, err)
			}
			pos += n
		}
	}

	return pos, nil
}
