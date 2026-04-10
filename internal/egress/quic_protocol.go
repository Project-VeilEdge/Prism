package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	QUICDatagramMagic   uint32 = 0x50525144 // "PRQD"
	QUICDatagramVersion uint16 = 0x0001

	QUICFrameOpen  byte = 0x01
	QUICFrameData  byte = 0x02
	QUICFrameClose byte = 0x03

	quicDatagramHeaderSize    = 38
	MaxQUICDatagramPayloadLen = 65535
)

const (
	quicOffMagic      = 0
	quicOffVersion    = 4
	quicOffType       = 6
	quicOffReserved   = 7
	quicOffSessionID  = 8
	quicOffTargetIP   = 16
	quicOffTargetPort = 32
	quicOffPayloadLen = 34
)

var (
	ErrShortQUICDatagramFrame   = errors.New("egress: QUIC datagram frame too short")
	ErrInvalidQUICDatagramMagic = errors.New("egress: invalid QUIC datagram magic")
	ErrInvalidQUICVersion       = errors.New("egress: unsupported QUIC datagram version")
	ErrQUICPayloadTooLarge      = errors.New("egress: QUIC datagram payload exceeds maximum")
)

type QUICDatagramFrame struct {
	Type       byte
	Reserved   byte
	SessionID  uint64
	TargetIP   net.IP
	TargetPort uint16
	Payload    []byte
}

func MarshalQUICDatagramFrame(f *QUICDatagramFrame) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("egress: nil QUIC datagram frame")
	}
	if len(f.Payload) > MaxQUICDatagramPayloadLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrQUICPayloadTooLarge, len(f.Payload), MaxQUICDatagramPayloadLen)
	}

	ip16 := net.IPv6zero.To16()
	if f.TargetIP != nil {
		ip16 = f.TargetIP.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("egress: invalid QUIC target IP: %v", f.TargetIP)
		}
	}

	buf := make([]byte, quicDatagramHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[quicOffMagic:], QUICDatagramMagic)
	binary.BigEndian.PutUint16(buf[quicOffVersion:], QUICDatagramVersion)
	buf[quicOffType] = f.Type
	buf[quicOffReserved] = f.Reserved
	binary.BigEndian.PutUint64(buf[quicOffSessionID:], f.SessionID)
	copy(buf[quicOffTargetIP:quicOffTargetIP+16], ip16)
	binary.BigEndian.PutUint16(buf[quicOffTargetPort:], f.TargetPort)
	binary.BigEndian.PutUint32(buf[quicOffPayloadLen:], uint32(len(f.Payload)))
	copy(buf[quicDatagramHeaderSize:], f.Payload)
	return buf, nil
}

func UnmarshalQUICDatagramFrame(buf []byte) (*QUICDatagramFrame, error) {
	if len(buf) < quicDatagramHeaderSize {
		return nil, ErrShortQUICDatagramFrame
	}
	if got := binary.BigEndian.Uint32(buf[quicOffMagic:]); got != QUICDatagramMagic {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrInvalidQUICDatagramMagic, got)
	}
	if got := binary.BigEndian.Uint16(buf[quicOffVersion:]); got != QUICDatagramVersion {
		return nil, fmt.Errorf("%w: got 0x%04X", ErrInvalidQUICVersion, got)
	}

	payloadLen := binary.BigEndian.Uint32(buf[quicOffPayloadLen:])
	if payloadLen > MaxQUICDatagramPayloadLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrQUICPayloadTooLarge, payloadLen, MaxQUICDatagramPayloadLen)
	}
	if len(buf) < quicDatagramHeaderSize+int(payloadLen) {
		return nil, ErrShortQUICDatagramFrame
	}

	frame := &QUICDatagramFrame{
		Type:       buf[quicOffType],
		Reserved:   buf[quicOffReserved],
		SessionID:  binary.BigEndian.Uint64(buf[quicOffSessionID:]),
		TargetIP:   append(net.IP(nil), buf[quicOffTargetIP:quicOffTargetIP+16]...),
		TargetPort: binary.BigEndian.Uint16(buf[quicOffTargetPort:]),
		Payload:    append([]byte(nil), buf[quicDatagramHeaderSize:quicDatagramHeaderSize+int(payloadLen)]...),
	}
	return frame, nil
}

func ReadQUICDatagramFrame(r io.Reader) (*QUICDatagramFrame, error) {
	header := make([]byte, quicDatagramHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("egress: read QUIC datagram frame header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint32(header[quicOffPayloadLen:])
	if payloadLen > MaxQUICDatagramPayloadLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrQUICPayloadTooLarge, payloadLen, MaxQUICDatagramPayloadLen)
	}

	buf := make([]byte, quicDatagramHeaderSize+int(payloadLen))
	copy(buf, header)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, buf[quicDatagramHeaderSize:]); err != nil {
			return nil, fmt.Errorf("egress: read QUIC datagram frame payload: %w", err)
		}
	}
	return UnmarshalQUICDatagramFrame(buf)
}

func WriteQUICDatagramFrame(w io.Writer, f *QUICDatagramFrame) error {
	buf, err := MarshalQUICDatagramFrame(f)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
