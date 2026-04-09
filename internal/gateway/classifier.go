package gateway

import (
	"fmt"
	"log/slog"

	"prism/internal/ech"
	"prism/pkg/stream"
)

// TrafficType classifies the type of incoming connection.
type TrafficType int

const (
	// TrafficECH indicates a TLS ClientHello with an ECH extension.
	TrafficECH TrafficType = iota
	// TrafficTLS indicates a TLS ClientHello without ECH.
	TrafficTLS
	// TrafficNonTLS indicates the first record is not a valid TLS handshake.
	TrafficNonTLS
)

func (t TrafficType) String() string {
	switch t {
	case TrafficECH:
		return "ech"
	case TrafficTLS:
		return "tls"
	case TrafficNonTLS:
		return "non_tls"
	default:
		return "unknown"
	}
}

// ClassifyResult holds the output of connection classification.
type ClassifyResult struct {
	Type   TrafficType
	Record []byte           // the full TLS record bytes read from the connection
	Parsed *ech.ParseResult // non-nil only when Type == TrafficECH or TrafficTLS
}

// Classify reads the first TLS record from the connection using RecordReader
// and determines whether it contains ECH, is plain TLS, or is non-TLS.
//
// The caller is responsible for setting a read deadline before calling Classify
// (e.g., 5s first-read timeout) and for preserving the returned Record bytes
// via prefixConn for any subsequent TLS handshake.
func Classify(rr *stream.RecordReader) (*ClassifyResult, error) {
	record, err := rr.ReadRecord()
	if err != nil {
		return nil, fmt.Errorf("classify: read record: %w", err)
	}

	// Check content type — must be Handshake (0x16) for a ClientHello.
	if stream.ContentType(record) != stream.ContentTypeHandshake {
		slog.Debug("classify_non_tls", "content_type", fmt.Sprintf("0x%02x", record[0]))
		return &ClassifyResult{
			Type:   TrafficNonTLS,
			Record: record,
		}, nil
	}

	// Attempt to parse the ClientHello.
	parsed, err := ech.Parse(record)
	if err != nil {
		slog.Debug("classify_parse_failed", "err", err)
		return &ClassifyResult{
			Type:   TrafficNonTLS,
			Record: record,
		}, nil
	}

	if parsed.HasECH {
		return &ClassifyResult{
			Type:   TrafficECH,
			Record: record,
			Parsed: parsed,
		}, nil
	}

	return &ClassifyResult{
		Type:   TrafficTLS,
		Record: record,
		Parsed: parsed,
	}, nil
}
