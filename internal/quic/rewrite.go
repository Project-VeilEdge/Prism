package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

const quicInitialMinSize = 1200

// HandshakeMessageFromRecord strips a TLS record header and returns the raw
// handshake message bytes.
func HandshakeMessageFromRecord(record []byte) ([]byte, error) {
	if len(record) < 5 {
		return nil, errors.New("quic: TLS record too short")
	}
	if record[0] != 0x16 {
		return nil, fmt.Errorf("quic: not a handshake record (type=0x%02x)", record[0])
	}

	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) != 5+recordLen {
		return nil, errors.New("quic: TLS record length mismatch")
	}
	if recordLen < 4 {
		return nil, errors.New("quic: TLS handshake message too short")
	}

	handshake := make([]byte, recordLen)
	copy(handshake, record[5:])
	return handshake, nil
}

// RewriteInitialPacket reparses a QUIC Initial, replaces its ClientHello
// handshake bytes, and reseals the packet.
func RewriteInitialPacket(packet []byte, replacementHandshake []byte) ([]byte, error) {
	if err := validateClientHelloHandshake(replacementHandshake); err != nil {
		return nil, err
	}

	firstPacketLen, err := initialPacketLength(packet)
	if err != nil {
		return nil, err
	}

	parsed, err := ParseInitial(append([]byte(nil), packet...))
	if err != nil {
		return nil, err
	}

	salt := initialSaltForVersion(parsed.Version)
	if salt == nil {
		return nil, fmt.Errorf("quic: unsupported version 0x%08x", parsed.Version)
	}
	key, iv, hp, err := deriveInitialKeys(parsed.DCID, salt)
	if err != nil {
		return nil, fmt.Errorf("quic: derive keys: %w", err)
	}

	pnBytes := encodePacketNumber(parsed.PacketNum)
	plaintext, err := buildRewrittenPayload(parsed.Payload, replacementHandshake, firstPacketLen, len(pnBytes), len(parsed.DCID), len(parsed.SCID), len(parsed.Token))
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, len(packet)+len(replacementHandshake))
	header = append(header, initialFirstByte(parsed.Version, len(pnBytes)))
	header = binary.BigEndian.AppendUint32(header, parsed.Version)
	header = append(header, byte(len(parsed.DCID)))
	header = append(header, parsed.DCID...)
	header = append(header, byte(len(parsed.SCID)))
	header = append(header, parsed.SCID...)
	header = append(header, encodeVarIntForPacket(uint64(len(parsed.Token)))...)
	header = append(header, parsed.Token...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("quic: AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("quic: AES-GCM: %w", err)
	}

	ciphertextLen := len(plaintext) + aead.Overhead()
	payloadLen := uint64(len(pnBytes) + ciphertextLen)
	header = append(header, encodeVarIntForPacket(payloadLen)...)
	pnOffset := len(header)
	header = append(header, pnBytes...)

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < len(pnBytes); i++ {
		nonce[len(nonce)-len(pnBytes)+i] ^= pnBytes[i]
	}

	packetOut := make([]byte, len(header))
	copy(packetOut, header)
	packetOut = aead.Seal(packetOut, nonce, plaintext, header)

	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packetOut) {
		return nil, errors.New("quic: packet too short for header protection sample")
	}

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, fmt.Errorf("quic: HP cipher: %w", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, packetOut[sampleOffset:sampleOffset+16])
	packetOut[0] ^= mask[0] & 0x0f
	for i := 0; i < len(pnBytes); i++ {
		packetOut[pnOffset+i] ^= mask[1+i]
	}

	packetOut = append(packetOut, packet[firstPacketLen:]...)
	return packetOut, nil
}

func validateClientHelloHandshake(handshake []byte) error {
	if len(handshake) < 4 {
		return errors.New("quic: handshake message too short")
	}
	if handshake[0] != 0x01 {
		return fmt.Errorf("quic: not a ClientHello handshake (type=0x%02x)", handshake[0])
	}

	declaredLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if declaredLen != len(handshake)-4 {
		return errors.New("quic: handshake length mismatch")
	}
	return nil
}

func buildRewrittenPayload(originalPayload, replacementHandshake []byte, originalPacketLen, pnLen, dcidLen, scidLen, tokenLen int) ([]byte, error) {
	frames, err := rewriteInitialPayloadFrames(originalPayload, replacementHandshake)
	if err != nil {
		return nil, err
	}

	targetLen := originalPacketLen
	if targetLen < quicInitialMinSize {
		targetLen = quicInitialMinSize
	}

	baseHeaderLen := 1 + 4 + 1 + dcidLen + 1 + scidLen + len(encodeVarIntForPacket(uint64(tokenLen))) + tokenLen
	plaintextLen := len(frames)
	for {
		ciphertextLen := plaintextLen + 16
		payloadFieldLen := pnLen + ciphertextLen
		totalLen := baseHeaderLen + len(encodeVarIntForPacket(uint64(payloadFieldLen))) + payloadFieldLen
		if totalLen >= targetLen {
			break
		}
		plaintextLen += targetLen - totalLen
	}

	payload := make([]byte, plaintextLen)
	copy(payload, frames)
	return payload, nil
}

func rewriteInitialPayloadFrames(originalPayload, replacementHandshake []byte) ([]byte, error) {
	cryptoFrame := append([]byte{0x06, 0x00}, encodeVarIntForPacket(uint64(len(replacementHandshake)))...)
	cryptoFrame = append(cryptoFrame, replacementHandshake...)

	rewritten := make([]byte, 0, len(originalPayload)+len(replacementHandshake))
	insertedCrypto := false

	for pos := 0; pos < len(originalPayload); {
		frameType := originalPayload[pos]

		switch {
		case frameType == 0x00:
			pos++

		case frameType == 0x01:
			rewritten = append(rewritten, frameType)
			pos++

		case frameType == 0x02 || frameType == 0x03:
			start := pos
			pos++
			n, err := skipACKFrame(originalPayload[pos:], frameType == 0x03)
			if err != nil {
				return nil, fmt.Errorf("ACK frame: %w", err)
			}
			pos += n
			rewritten = append(rewritten, originalPayload[start:pos]...)

		case frameType == 0x06:
			if !insertedCrypto {
				rewritten = append(rewritten, cryptoFrame...)
				insertedCrypto = true
			}
			pos++

			_, n, err := readVarInt(originalPayload[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO offset: %w", err)
			}
			pos += n

			cryptoLen, n, err := readVarInt(originalPayload[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO length: %w", err)
			}
			pos += n

			if pos+int(cryptoLen) > len(originalPayload) {
				return nil, fmt.Errorf("CRYPTO data truncated: need %d, have %d", cryptoLen, len(originalPayload)-pos)
			}
			pos += int(cryptoLen)

		case frameType == 0x1c || frameType == 0x1d:
			start := pos
			pos++
			n, err := skipConnectionCloseFrame(originalPayload[pos:], frameType == 0x1c)
			if err != nil {
				return nil, fmt.Errorf("%s frame: %w", frameTypeName(frameType), err)
			}
			pos += n
			rewritten = append(rewritten, originalPayload[start:pos]...)

		default:
			return nil, fmt.Errorf("quic: unsupported Initial frame type 0x%02x (%s)", frameType, frameTypeName(frameType))
		}
	}

	if !insertedCrypto {
		return nil, errors.New("quic: no CRYPTO frame in Initial payload")
	}
	return rewritten, nil
}

func skipConnectionCloseFrame(data []byte, transportClose bool) (int, error) {
	pos := 0

	_, n, err := readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	if transportClose {
		_, n, err = readVarInt(data[pos:])
		if err != nil {
			return 0, err
		}
		pos += n
	}

	reasonLen, n, err := readVarInt(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	if pos+int(reasonLen) > len(data) {
		return 0, fmt.Errorf("reason phrase truncated: need %d, have %d", reasonLen, len(data)-pos)
	}
	pos += int(reasonLen)
	return pos, nil
}

func frameTypeName(frameType byte) string {
	switch frameType {
	case 0x00:
		return "PADDING"
	case 0x01:
		return "PING"
	case 0x02:
		return "ACK"
	case 0x03:
		return "ACK_ECN"
	case 0x04:
		return "RESET_STREAM"
	case 0x05:
		return "STOP_SENDING"
	case 0x06:
		return "CRYPTO"
	case 0x08:
		return "NEW_TOKEN"
	case 0x1c:
		return "CONNECTION_CLOSE"
	case 0x1d:
		return "APPLICATION_CLOSE"
	default:
		return "unknown"
	}
}

func initialPacketLength(packet []byte) (int, error) {
	if len(packet) < 6 {
		return 0, errors.New("quic: packet too short")
	}

	offset := 5
	if offset >= len(packet) {
		return 0, errors.New("quic: truncated DCID length")
	}
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen > len(packet) {
		return 0, errors.New("quic: truncated DCID")
	}
	offset += dcidLen

	if offset >= len(packet) {
		return 0, errors.New("quic: truncated SCID length")
	}
	scidLen := int(packet[offset])
	offset++
	if offset+scidLen > len(packet) {
		return 0, errors.New("quic: truncated SCID")
	}
	offset += scidLen

	tokenLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return 0, fmt.Errorf("quic: token length: %w", err)
	}
	offset += n
	if offset+int(tokenLen) > len(packet) {
		return 0, errors.New("quic: truncated token")
	}
	offset += int(tokenLen)

	payloadLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return 0, fmt.Errorf("quic: payload length: %w", err)
	}
	offset += n

	if offset+int(payloadLen) > len(packet) {
		return 0, errors.New("quic: truncated packet payload")
	}
	return offset + int(payloadLen), nil
}

func encodePacketNumber(packetNum uint32) []byte {
	switch {
	case packetNum <= 0xff:
		return []byte{byte(packetNum)}
	case packetNum <= 0xffff:
		return []byte{byte(packetNum >> 8), byte(packetNum)}
	case packetNum <= 0xffffff:
		return []byte{byte(packetNum >> 16), byte(packetNum >> 8), byte(packetNum)}
	default:
		return []byte{byte(packetNum >> 24), byte(packetNum >> 16), byte(packetNum >> 8), byte(packetNum)}
	}
}

func initialFirstByte(version uint32, pnLen int) byte {
	firstByte := byte(0xc0)
	if version == QUICVersion2 {
		firstByte = 0xd0
	}
	return firstByte | byte(pnLen-1)
}

func encodeVarIntForPacket(val uint64) []byte {
	switch {
	case val < 0x40:
		return []byte{byte(val)}
	case val < 0x4000:
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, uint16(val)|0x4000)
		return out
	case val < 0x40000000:
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(val)|0x80000000)
		return out
	default:
		out := make([]byte, 8)
		binary.BigEndian.PutUint64(out, val|0xc000000000000000)
		return out
	}
}
