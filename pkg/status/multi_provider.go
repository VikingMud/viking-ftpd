package status

import "time"

// MultiProvider aggregates metrics from multiple servers (e.g. FTP + SFTP)
// into a single MetricsProvider for the status writer.
type MultiProvider struct {
	providers []MetricsProvider
}

// NewMultiProvider creates a MetricsProvider that sums connection counts
// across the given providers and reports the earliest start time.
func NewMultiProvider(providers ...MetricsProvider) *MultiProvider {
	return &MultiProvider{providers: providers}
}

// GetActiveConnections returns the sum of active connections across providers
func (m *MultiProvider) GetActiveConnections() int32 {
	var total int32
	for _, p := range m.providers {
		total += p.GetActiveConnections()
	}
	return total
}

// GetTotalConnections returns the sum of total connections across providers
func (m *MultiProvider) GetTotalConnections() int64 {
	var total int64
	for _, p := range m.providers {
		total += p.GetTotalConnections()
	}
	return total
}

// GetStartTime returns the earliest non-zero start time across providers
func (m *MultiProvider) GetStartTime() time.Time {
	var earliest time.Time
	for _, p := range m.providers {
		t := p.GetStartTime()
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}
