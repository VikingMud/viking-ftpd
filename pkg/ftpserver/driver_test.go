package ftpserver

import (
	"testing"
	"time"

	ftpserverlib "github.com/fclairamb/ftpserverlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	if cfg.RootDir == "" {
		cfg.RootDir = t.TempDir()
	}
	s, err := New(cfg, nil, nil, "test")
	require.NoError(t, err)
	return s
}

func TestGetSettings(t *testing.T) {
	s := newTestServer(t, &Config{
		ListenAddr:    "127.0.0.1",
		Port:          2121,
		PasvPortRange: [2]int{50000, 50100},
		PasvAddress:   "203.0.113.1",
		PasvIPVerify:  true,
		IdleTimeout:   5 * time.Minute,
	})
	d := &ftpDriver{server: s}

	settings, err := d.GetSettings()
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:2121", settings.ListenAddr)
	assert.Equal(t, 50000, settings.PassiveTransferPortRange.Start)
	assert.Equal(t, 50100, settings.PassiveTransferPortRange.End)
	assert.True(t, settings.DisableActiveMode)
	assert.Equal(t, ftpserverlib.ClearOrEncrypted, settings.TLSRequired)
	assert.Equal(t, "203.0.113.1", settings.PublicHost)
	assert.Equal(t, ftpserverlib.IPMatchRequired, settings.PasvConnectionsCheck)
	// Duration is converted to whole seconds for ftpserverlib.
	assert.Equal(t, 300, settings.IdleTimeout)
}

func TestGetSettingsIPv6(t *testing.T) {
	s := newTestServer(t, &Config{ListenAddr: "::1", Port: 2121, PasvPortRange: [2]int{50000, 50100}})
	d := &ftpDriver{server: s}

	settings, err := d.GetSettings()
	require.NoError(t, err)
	assert.Equal(t, "[::1]:2121", settings.ListenAddr, "IPv6 host must be bracketed")
}

func TestGetSettingsPasvVerifyDisabled(t *testing.T) {
	s := newTestServer(t, &Config{ListenAddr: "0.0.0.0", Port: 2121, PasvPortRange: [2]int{50000, 50100}})
	d := &ftpDriver{server: s}

	settings, err := d.GetSettings()
	require.NoError(t, err)
	assert.Equal(t, ftpserverlib.IPMatchDisabled, settings.PasvConnectionsCheck)
	assert.Empty(t, settings.PublicHost)
}

func TestGetTLSConfig(t *testing.T) {
	t.Run("no cert configured returns sentinel", func(t *testing.T) {
		s := newTestServer(t, &Config{})
		d := &ftpDriver{server: s}
		_, err := d.GetTLSConfig()
		assert.ErrorIs(t, err, errNoTLS)
	})

	t.Run("missing cert file errors", func(t *testing.T) {
		s := newTestServer(t, &Config{
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  "/nonexistent/key.pem",
		})
		d := &ftpDriver{server: s}
		_, err := d.GetTLSConfig()
		require.Error(t, err)
		assert.NotErrorIs(t, err, errNoTLS)
	})
}

// TestClientConnectedEnforcesMaxConnections verifies the connection limit and
// that the counters stay balanced across the refusal path (ClientDisconnected
// still runs for a refused connection).
func TestClientConnectedEnforcesMaxConnections(t *testing.T) {
	s := newTestServer(t, &Config{MaxConnections: 2})
	d := &ftpDriver{server: s}
	cc := &fakeContext{}

	_, err1 := d.ClientConnected(cc)
	_, err2 := d.ClientConnected(cc)
	_, err3 := d.ClientConnected(cc)

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Error(t, err3, "third connection over the limit of 2 must be refused")

	assert.Equal(t, int32(3), s.GetActiveConnections(), "all three increment active")
	assert.Equal(t, int64(2), s.GetTotalConnections(), "only accepted connections count toward total")

	// ftpserverlib calls ClientDisconnected for every connection, including the
	// refused one; the active count must return to zero.
	d.ClientDisconnected(cc)
	d.ClientDisconnected(cc)
	d.ClientDisconnected(cc)
	assert.Equal(t, int32(0), s.GetActiveConnections())
}

func TestClientConnectedUnlimited(t *testing.T) {
	s := newTestServer(t, &Config{MaxConnections: 0}) // 0 = unlimited
	d := &ftpDriver{server: s}
	cc := &fakeContext{}

	for i := 0; i < 20; i++ {
		_, err := d.ClientConnected(cc)
		require.NoError(t, err)
	}
	assert.Equal(t, int64(20), s.GetTotalConnections())
}
