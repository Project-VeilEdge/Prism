// Package pool provides sync.Pool-based buffer pools for relay and I/O paths.
package pool

import "sync"

const (
	// RelayBufSize is the standard buffer size for bidirectional relay.
	// 16KB matches the maximum TLS record payload (16384 bytes).
	RelayBufSize = 16 * 1024
)

// relayPool holds 16KB byte slices for io.CopyBuffer in the relay path.
var relayPool = sync.Pool{
	New: func() any {
		buf := make([]byte, RelayBufSize)
		return &buf
	},
}

// GetRelayBuf obtains a 16KB buffer from the pool.
// The caller MUST call PutRelayBuf when done.
func GetRelayBuf() *[]byte {
	return relayPool.Get().(*[]byte)
}

// PutRelayBuf returns a buffer to the pool.
func PutRelayBuf(buf *[]byte) {
	if buf == nil {
		return
	}
	relayPool.Put(buf)
}
