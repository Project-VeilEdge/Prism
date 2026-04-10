package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"
)

type QUICEgressServer struct {
	DenyPrivateTargets bool
}

func writeQUICOpenError(conn net.Conn, writeMu *sync.Mutex, frame *QUICDatagramFrame, err error) {
	if conn == nil || writeMu == nil || frame == nil || err == nil {
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	_ = WriteQUICDatagramFrame(conn, &QUICDatagramFrame{
		Type:       QUICFrameClose,
		SessionID:  frame.SessionID,
		TargetIP:   frame.TargetIP,
		TargetPort: frame.TargetPort,
		Payload:    []byte(err.Error()),
	})
}

func (s *QUICEgressServer) Serve(conn net.Conn, reader *bufio.Reader) error {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}

	var (
		sessionID uint64
		udpConn   *net.UDPConn
		target    *net.UDPAddr
		writeMu   sync.Mutex
	)
	relayErrCh := make(chan error, 1)

	closeUDP := func() {
		if udpConn != nil {
			_ = udpConn.Close()
			udpConn = nil
		}
	}
	defer closeUDP()

	for {
		frame, err := ReadQUICDatagramFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch frame.Type {
		case QUICFrameOpen:
			if udpConn != nil {
				return fmt.Errorf("egress: QUIC datagram session already open")
			}
			ip16 := frame.TargetIP.To16()
			if ip16 == nil {
				err := fmt.Errorf("egress: invalid QUIC target IP: %v", frame.TargetIP)
				writeQUICOpenError(conn, &writeMu, frame, err)
				return err
			}
			if s.DenyPrivateTargets && isPrivateIP(frame.TargetIP) {
				err := fmt.Errorf("egress: QUIC target IP denied: %v", frame.TargetIP)
				writeQUICOpenError(conn, &writeMu, frame, err)
				return err
			}

			target = &net.UDPAddr{IP: append(net.IP(nil), ip16...), Port: int(frame.TargetPort)}
			sessionID = frame.SessionID
			udpConn, err = net.DialUDP("udp", nil, target)
			if err != nil {
				err = fmt.Errorf("egress: dial UDP target %s: %w", target.String(), err)
				writeQUICOpenError(conn, &writeMu, frame, err)
				return err
			}

			if len(frame.Payload) > 0 {
				if _, err := udpConn.Write(frame.Payload); err != nil {
					err = fmt.Errorf("egress: write initial QUIC datagram: %w", err)
					writeQUICOpenError(conn, &writeMu, frame, err)
					return err
				}
			}

			writeMu.Lock()
			err = WriteQUICDatagramFrame(conn, &QUICDatagramFrame{
				Type:       QUICFrameOpen,
				SessionID:  sessionID,
				TargetIP:   target.IP,
				TargetPort: uint16(target.Port),
			})
			writeMu.Unlock()
			if err != nil {
				return fmt.Errorf("egress: acknowledge QUIC datagram session: %w", err)
			}

			go func(sessionID uint64, target *net.UDPAddr, udpConn *net.UDPConn) {
				buf := make([]byte, MaxQUICDatagramPayloadLen)
				for {
					n, err := udpConn.Read(buf)
					if err != nil {
						select {
						case relayErrCh <- nil:
						default:
						}
						return
					}
					payload := append([]byte(nil), buf[:n]...)
					writeMu.Lock()
					writeErr := WriteQUICDatagramFrame(conn, &QUICDatagramFrame{
						Type:       QUICFrameData,
						SessionID:  sessionID,
						TargetIP:   target.IP,
						TargetPort: uint16(target.Port),
						Payload:    payload,
					})
					writeMu.Unlock()
					if writeErr != nil {
						select {
						case relayErrCh <- writeErr:
						default:
						}
						return
					}
				}
			}(sessionID, target, udpConn)

		case QUICFrameData:
			if udpConn == nil {
				return fmt.Errorf("egress: QUIC datagram session not open")
			}
			if frame.SessionID != sessionID {
				return fmt.Errorf("egress: unexpected QUIC session ID %d", frame.SessionID)
			}
			if len(frame.Payload) == 0 {
				continue
			}
			if _, err := udpConn.Write(frame.Payload); err != nil {
				return fmt.Errorf("egress: write QUIC datagram: %w", err)
			}

		case QUICFrameClose:
			if udpConn == nil {
				return nil
			}
			if frame.SessionID != sessionID {
				return fmt.Errorf("egress: unexpected QUIC session ID %d", frame.SessionID)
			}
			closeUDP()
			return nil

		default:
			return fmt.Errorf("egress: unsupported QUIC frame type %d", frame.Type)
		}

		select {
		case err := <-relayErrCh:
			if err != nil {
				return err
			}
		default:
		}
	}
}
