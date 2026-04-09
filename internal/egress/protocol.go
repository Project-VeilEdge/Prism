// Package egress implements the egress routing engine, GeoIP lookup,
// and the Gateway↔Egress binary frame protocol.
package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// FrameSize is the fixed 68-byte header size for Gateway↔Egress communication.
	FrameSize = 68

	// Magic is the 4-byte magic number "PRIS" (0x50524953).
	Magic uint32 = 0x50524953

	// Version is the current protocol version.
	Version uint16 = 0x0001

	// MaxInnerCHLen is the maximum allowed InnerCHLen value.
	// A TLS ClientHello fits in one record (max 16640 bytes per RFC 8446).
	// We use the same bound as pkg/stream.MaxRecordPayload.
	MaxInnerCHLen uint32 = 16640

	// offsets within the frame
	offMagic      = 0
	offVersion    = 4
	offInnerCHLen = 6
	offTargetIP   = 10
	offTargetPort = 26
	offReserved   = 28
)

// Frame represents the 68-byte binary header sent from Gateway to Egress.
type Frame struct {
	InnerCHLen uint32
	TargetIP   net.IP // always 16-byte (IPv4-mapped-to-IPv6)
	TargetPort uint16
}

var (
	ErrInvalidMagic   = errors.New("egress: invalid frame magic")
	ErrInvalidVersion = errors.New("egress: unsupported frame version")
	ErrShortFrame     = errors.New("egress: frame too short")
	ErrInnerCHTooLong = errors.New("egress: InnerCHLen exceeds maximum")
)

// MarshalFrame serializes a Frame into a 68-byte buffer.
// IPv4 addresses are automatically mapped to IPv6.
// Returns an error if TargetIP is nil or not a valid IP address.
func MarshalFrame(f *Frame) ([]byte, error) {
	ip16 := f.TargetIP.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("egress: invalid target IP: %v", f.TargetIP)
	}

	buf := make([]byte, FrameSize)

	binary.BigEndian.PutUint32(buf[offMagic:], Magic)
	binary.BigEndian.PutUint16(buf[offVersion:], Version)
	binary.BigEndian.PutUint32(buf[offInnerCHLen:], f.InnerCHLen)

	copy(buf[offTargetIP:offTargetIP+16], ip16)

	binary.BigEndian.PutUint16(buf[offTargetPort:], f.TargetPort)
	// [28:68] reserved, already zero

	return buf, nil
}

// UnmarshalFrame deserializes a 68-byte buffer into a Frame.
func UnmarshalFrame(buf []byte) (*Frame, error) {
	if len(buf) < FrameSize {
		return nil, ErrShortFrame
	}

	magic := binary.BigEndian.Uint32(buf[offMagic:])
	if magic != Magic {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrInvalidMagic, magic)
	}

	version := binary.BigEndian.Uint16(buf[offVersion:])
	if version != Version {
		return nil, fmt.Errorf("%w: got 0x%04X", ErrInvalidVersion, version)
	}

	f := &Frame{
		InnerCHLen: binary.BigEndian.Uint32(buf[offInnerCHLen:]),
		TargetIP:   make(net.IP, 16),
		TargetPort: binary.BigEndian.Uint16(buf[offTargetPort:]),
	}
	copy(f.TargetIP, buf[offTargetIP:offTargetIP+16])

	if f.InnerCHLen > MaxInnerCHLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrInnerCHTooLong, f.InnerCHLen, MaxInnerCHLen)
	}

	return f, nil
}

// ReadFrame reads exactly 68 bytes from r and parses a Frame.
func ReadFrame(r io.Reader) (*Frame, error) {
	buf := make([]byte, FrameSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("egress: read frame: %w", err)
	}
	return UnmarshalFrame(buf)
}

// WriteFrame serializes the frame and writes it to w.
func WriteFrame(w io.Writer, f *Frame) error {
	buf, err := MarshalFrame(f)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
