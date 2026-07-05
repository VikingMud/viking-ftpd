package status

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type fakeProvider struct {
	active    int32
	total     int64
	startTime time.Time
}

func (f *fakeProvider) GetActiveConnections() int32 { return f.active }
func (f *fakeProvider) GetTotalConnections() int64  { return f.total }
func (f *fakeProvider) GetStartTime() time.Time     { return f.startTime }

func TestMultiProvider(t *testing.T) {
	earlier := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := earlier.Add(time.Hour)

	m := NewMultiProvider(
		&fakeProvider{active: 2, total: 10, startTime: later},
		&fakeProvider{active: 3, total: 5, startTime: earlier},
	)

	assert.Equal(t, int32(5), m.GetActiveConnections())
	assert.Equal(t, int64(15), m.GetTotalConnections())
	assert.Equal(t, earlier, m.GetStartTime())
}

func TestMultiProviderIgnoresZeroStartTimes(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	m := NewMultiProvider(
		&fakeProvider{},
		&fakeProvider{startTime: start},
	)

	assert.Equal(t, start, m.GetStartTime())
}

func TestMultiProviderEmpty(t *testing.T) {
	m := NewMultiProvider()

	assert.Equal(t, int32(0), m.GetActiveConnections())
	assert.Equal(t, int64(0), m.GetTotalConnections())
	assert.True(t, m.GetStartTime().IsZero())
}
