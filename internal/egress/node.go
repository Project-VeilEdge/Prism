package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"prism/internal/relay"
	"prism/pkg/connutil"
	"prism/pkg/stream"
)

const (
	dialTimeout        = 5 * time.Second
	firstRecordTimeout = 5 * time.Second
)

// Client represents the egress client running on the Gateway side.
// It dials a remote egress node over mTLS, sends the 68-byte frame header
// and the inner ClientHello, then relays bidirectionally.
type Client struct {
	TLSConfig *tls.Config
}

// ForwardResult contains metrics from a completed egress forward.
type ForwardResult struct {
	UpBytes   int64
	DownBytes int64
}

// Forward connects to the given egress node, sends the frame + inner CH,
// then relays traffic between the browser connection and the egress node.
// innerCHRecord is the full TLS record (with 5B record header) to forward.
func (c *Client) Forward(
	ctx context.Context,
	node *EgressNode,
	clientConn net.Conn,
	targetIP net.IP,
	targetPort uint16,
	innerCHRecord []byte,
) (*ForwardResult, error) {
	if node.IsDirect() {
		return nil, fmt.Errorf("egress: cannot forward via direct node")
	}

	// Dial the egress node with mTLS
	dialer := &tls.Dialer{
		Config: c.TLSConfig,
		NetDialer: &net.Dialer{
			Timeout: dialTimeout,
		},
	}

	egressConn, err := dialer.DialContext(ctx, "tcp", node.Address)
	if err != nil {
		return nil, fmt.Errorf("egress: dial %s (%s): %w", node.Name, node.Address, err)
	}

	// Set a write deadline for the frame + inner CH exchange
	if err := egressConn.SetWriteDeadline(stageDeadline(ctx, dialTimeout)); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: set write deadline: %w", err)
	}

	// Write the 68-byte frame header
	frame := &Frame{
		InnerCHLen: uint32(len(innerCHRecord)),
		TargetIP:   targetIP,
		TargetPort: targetPort,
	}
	if err := WriteFrame(egressConn, frame); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: write frame to %s: %w", node.Name, err)
	}

	// Write the inner ClientHello record
	if _, err := egressConn.Write(innerCHRecord); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: write inner CH to %s: %w", node.Name, err)
	}

	if err := ctx.Err(); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: context expired before first TLS record from %s: %w", node.Name, err)
	}

	// Wait for the first upstream TLS record before committing the route. If the
	// remote egress node closes early (e.g. target dial failure), surface that as
	// an error so the gateway can fall back to the next route.
	if err := egressConn.SetReadDeadline(stageDeadline(ctx, firstRecordTimeout)); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: set read deadline: %w", err)
	}
	firstRecord, err := stream.NewRecordReader(egressConn).ReadRecord()
	if err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: read first TLS record from %s: %w", node.Name, err)
	}

	// Clear deadlines for relay phase
	if err := egressConn.SetDeadline(time.Time{}); err != nil {
		egressConn.Close()
		return nil, fmt.Errorf("egress: clear deadline: %w", err)
	}

	slog.Debug("egress_forward_start",
		"node", node.Name,
		"target_ip", targetIP,
		"target_port", targetPort,
	)

	relayConn := connutil.NewPrefixConn(egressConn, firstRecord)

	// Relay bidirectionally
	upWriter, downWriter := relay.NewRelayPair(clientConn, relayConn)
	relay.RelayWithMetrics(clientConn, relayConn, upWriter, downWriter)

	return &ForwardResult{
		UpBytes:   upWriter.Bytes(),
		DownBytes: downWriter.Bytes(),
	}, nil
}

func stageDeadline(ctx context.Context, stageTimeout time.Duration) time.Time {
	deadline := time.Now().Add(stageTimeout)
	if ctx == nil {
		return deadline
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}
