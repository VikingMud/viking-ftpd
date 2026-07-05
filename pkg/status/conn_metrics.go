package status

import (
	"sync/atomic"
	"time"
)

// ConnMetrics holds the connection counters shared by the FTP and SFTP
// servers. Embed it by value in a server; its Get* methods satisfy
// MetricsProvider, and the counters are safe for concurrent use.
//
// The three mutators are separate (rather than a single "open") so callers can
// enforce a connection limit before deciding whether a connection counts
// toward the lifetime total: increment the active count, and only if the
// connection is accepted increment the total.
type ConnMetrics struct {
	active    atomic.Int32
	total     atomic.Int64
	startTime time.Time
}

// SetStartTime records the server start time. Call once before serving; the
// value is read-only afterward.
func (m *ConnMetrics) SetStartTime(t time.Time) { m.startTime = t }

// IncActive increments the active-connection count and returns the new value.
func (m *ConnMetrics) IncActive() int32 { return m.active.Add(1) }

// DecActive decrements the active-connection count.
func (m *ConnMetrics) DecActive() { m.active.Add(-1) }

// IncTotal increments the lifetime connection count.
func (m *ConnMetrics) IncTotal() { m.total.Add(1) }

// GetActiveConnections returns the current number of active connections.
func (m *ConnMetrics) GetActiveConnections() int32 { return m.active.Load() }

// GetTotalConnections returns the total number of connections since start.
func (m *ConnMetrics) GetTotalConnections() int64 { return m.total.Load() }

// GetStartTime returns the recorded server start time.
func (m *ConnMetrics) GetStartTime() time.Time { return m.startTime }
