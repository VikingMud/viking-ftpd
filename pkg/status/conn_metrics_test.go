package status

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnMetrics(t *testing.T) {
	var m ConnMetrics
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.SetStartTime(start)

	assert.Equal(t, int32(0), m.GetActiveConnections())
	assert.Equal(t, int64(0), m.GetTotalConnections())
	assert.Equal(t, start, m.GetStartTime())

	assert.Equal(t, int32(1), m.IncActive())
	assert.Equal(t, int32(2), m.IncActive())
	m.IncTotal()
	m.IncTotal()
	m.DecActive()

	assert.Equal(t, int32(1), m.GetActiveConnections())
	assert.Equal(t, int64(2), m.GetTotalConnections())
}

// TestConnMetricsSatisfiesProvider ensures ConnMetrics can back the status
// writer directly.
func TestConnMetricsSatisfiesProvider(t *testing.T) {
	var m ConnMetrics
	var _ MetricsProvider = &m
}

func TestConnMetricsConcurrent(t *testing.T) {
	var m ConnMetrics
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			m.IncActive()
			m.IncTotal()
			m.DecActive()
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(0), m.GetActiveConnections())
	assert.Equal(t, int64(goroutines), m.GetTotalConnections())
}
