package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type DatagramSession interface {
	Write([]byte) error
	Read(context.Context) ([]byte, error)
	Close() error
}

type QUICClient struct {
	TLSConfig     *tls.Config
	DialContext   func(ctx context.Context, network, address string) (net.Conn, error)
	nextSessionID atomic.Uint64
}

type QUICSession struct {
	conn       net.Conn
	sessionID  uint64
	targetIP   net.IP
	targetPort uint16

	writeMu   sync.Mutex
	closeOnce sync.Once
}

func (c *QUICClient) OpenSession(
	ctx context.Context,
	node *EgressNode,
	targetIP net.IP,
	targetPort uint16,
	firstDatagram []byte,
) (DatagramSession, error) {
	if node == nil {
		return nil, fmt.Errorf("egress: nil QUIC node")
	}
	if node.IsDirect() {
		return nil, fmt.Errorf("egress: cannot open QUIC session via direct node")
	}

	conn, err := c.dialContext(ctx, "tcp", node.Address)
	if err != nil {
		return nil, fmt.Errorf("egress: dial QUIC node %s (%s): %w", node.Name, node.Address, err)
	}

	session := &QUICSession{
		conn:       conn,
		sessionID:  c.nextSessionID.Add(1),
		targetIP:   append(net.IP(nil), targetIP...),
		targetPort: targetPort,
	}

	if err := session.writeFrame(&QUICDatagramFrame{
		Type:       QUICFrameOpen,
		SessionID:  session.sessionID,
		TargetIP:   targetIP,
		TargetPort: targetPort,
		Payload:    firstDatagram,
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("egress: open QUIC session: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dialTimeout)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("egress: set QUIC open read deadline: %w", err)
	}
	frame, err := ReadQUICDatagramFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("egress: await QUIC open response: %w", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("egress: clear QUIC open read deadline: %w", err)
	}
	if frame.SessionID != session.sessionID {
		_ = conn.Close()
		return nil, fmt.Errorf("egress: unexpected QUIC open response session %d", frame.SessionID)
	}
	switch frame.Type {
	case QUICFrameOpen:
		return session, nil
	case QUICFrameClose:
		_ = conn.Close()
		if len(frame.Payload) > 0 {
			return nil, fmt.Errorf("egress: open QUIC session rejected: %s", string(frame.Payload))
		}
		return nil, fmt.Errorf("egress: open QUIC session rejected")
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("egress: unexpected QUIC open response type %d", frame.Type)
	}

}

func (c *QUICClient) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c != nil && c.DialContext != nil {
		return c.DialContext(ctx, network, address)
	}

	dialer := &tls.Dialer{
		Config: c.TLSConfig,
		NetDialer: &net.Dialer{
			Timeout: dialTimeout,
		},
	}
	return dialer.DialContext(ctx, network, address)
}

func (s *QUICSession) Write(datagram []byte) error {
	return s.writeFrame(&QUICDatagramFrame{
		Type:       QUICFrameData,
		SessionID:  s.sessionID,
		TargetIP:   s.targetIP,
		TargetPort: s.targetPort,
		Payload:    datagram,
	})
}

func (s *QUICSession) Read(ctx context.Context) ([]byte, error) {
	for {
		deadline, hasDeadline := ctx.Deadline()
		if !hasDeadline {
			deadline = time.Now().Add(250 * time.Millisecond)
		}
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}

		frame, err := ReadQUICDatagramFrame(s.conn)
		if err != nil {
			if !hasDeadline {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					continue
				}
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, err
		}

		if frame.SessionID != s.sessionID {
			continue
		}

		switch frame.Type {
		case QUICFrameData:
			return frame.Payload, nil
		case QUICFrameClose:
			return nil, io.EOF
		default:
			continue
		}
	}
}

func (s *QUICSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		_ = s.writeFrame(&QUICDatagramFrame{
			Type:       QUICFrameClose,
			SessionID:  s.sessionID,
			TargetIP:   s.targetIP,
			TargetPort: s.targetPort,
		})
		closeErr = s.conn.Close()
	})
	return closeErr
}

func (s *QUICSession) writeFrame(frame *QUICDatagramFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.conn.SetWriteDeadline(time.Now().Add(dialTimeout)); err != nil {
		return err
	}
	defer func() {
		_ = s.conn.SetWriteDeadline(time.Time{})
	}()

	return WriteQUICDatagramFrame(s.conn, frame)
}
