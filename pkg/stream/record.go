// Package stream provides low-level TLS record reading primitives.
// It operates on raw bytes with zero TLS state — no handshake, no crypto.
package stream

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// RecordHeaderSize is the fixed 5-byte TLS record header:
	//   [0]   content_type  (1 byte)
	//   [1:3] protocol_version (2 bytes, e.g. 0x0303 = TLS 1.2)
	//   [3:5] payload_length (2 bytes, big-endian)
	RecordHeaderSize = 5

	// MaxRecordPayload is the RFC 8446 maximum: 2^14 (16384) + 256 bytes
	// for encrypted overhead. Any record claiming more is malicious.
	MaxRecordPayload = 16384 + 256 // 16640

	// ContentTypeHandshake is TLS content type for handshake messages.
	ContentTypeHandshake = 0x16
)

// NotTLSError is returned when the first byte of the stream is not a valid
// TLS content type (0x14-0x18). This typically means the client sent plain
// HTTP, SSH, or other non-TLS traffic.
type NotTLSError struct {
	FirstByte byte
}

func (e *NotTLSError) Error() string {
	return fmt.Sprintf("not a TLS record: first byte 0x%02x (expected 0x14-0x18)", e.FirstByte)
}

// RecordReader reads exactly one complete TLS record from an io.Reader.
// It is safe against slow readers (one byte at a time) and oversized records.
type RecordReader struct {
	r io.Reader
}

// NewRecordReader wraps r for TLS record-level reading.
func NewRecordReader(r io.Reader) *RecordReader {
	return &RecordReader{r: r}
}

// ReadRecord reads one complete TLS record. Returns the full record bytes
// including the 5-byte header. The returned slice is freshly allocated.
//
// Wire format:
//
//	[0]     content_type
//	[1:3]   version (major, minor)
//	[3:5]   payload_length  (big-endian uint16)
//	[5:]    payload          (payload_length bytes)
func (rr *RecordReader) ReadRecord() ([]byte, error) {
	// Step 1: Read the 5-byte record header.
	var hdr [RecordHeaderSize]byte
	if _, err := io.ReadFull(rr.r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read record header: %w", err)
	}

	// Step 2: Validate content type is a known TLS type (0x14-0x18).
	if hdr[0] < 0x14 || hdr[0] > 0x18 {
		return nil, &NotTLSError{FirstByte: hdr[0]}
	}

	// Step 3: Extract payload length from header bytes [3:5].
	payloadLen := int(binary.BigEndian.Uint16(hdr[3:5]))

	// Step 4: Reject zero-length records (invalid per RFC 8446 §5.1).
	if payloadLen == 0 {
		return nil, fmt.Errorf("record payload length is zero")
	}

	// Step 5: Reject oversized records before allocating.
	if payloadLen > MaxRecordPayload {
		return nil, fmt.Errorf("record payload %d bytes exceeds maximum %d", payloadLen, MaxRecordPayload)
	}

	// Step 6: Allocate full record buffer and copy header.
	record := make([]byte, RecordHeaderSize+payloadLen)
	copy(record[:RecordHeaderSize], hdr[:])

	// Step 7: Read the payload body. io.ReadFull handles slow/partial reads.
	if _, err := io.ReadFull(rr.r, record[RecordHeaderSize:]); err != nil {
		return nil, fmt.Errorf("read record payload (%d bytes): %w", payloadLen, err)
	}

	return record, nil
}

// ContentType extracts the content type byte from a TLS record.
func ContentType(record []byte) byte {
	if len(record) < 1 {
		return 0
	}
	return record[0]
}

// PayloadLen extracts the payload length from a TLS record header.
func PayloadLen(record []byte) int {
	if len(record) < RecordHeaderSize {
		return 0
	}
	return int(binary.BigEndian.Uint16(record[3:5]))
}
