package sftpserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/mmcdole/viking-ftpd/pkg/status"
	"github.com/mmcdole/viking-ftpd/pkg/users"
	"github.com/mmcdole/viking-ftpd/pkg/vfs"
)

// handshakeTimeout bounds how long a client may take to complete the SSH
// handshake and authentication, so half-open pre-auth connections can't
// accumulate.
const handshakeTimeout = 30 * time.Second

// Authenticator verifies user credentials. Satisfied by
// *authentication.Authenticator.
type Authenticator interface {
	Authenticate(username, password string) (*users.User, error)
}

// Config holds the server configuration
type Config struct {
	ListenAddr     string        // Address to listen on
	Port           int           // Port to listen on
	RootDir        string        // Root directory that SFTP users will be restricted to
	HomePattern    string        // Pattern for user home directories (e.g., "players/%s")
	HostKeyFile    string        // Path to the SSH host key (generated if missing)
	IdleTimeout    time.Duration // Connection idle timeout (0 = none)
	MaxConnections int           // Maximum concurrent connections (0 = unlimited)
}

// Server is an SFTP server that enforces the same authentication,
// authorization, and filesystem jail as the FTP server.
type Server struct {
	config        *Config
	authenticator Authenticator
	authorizer    vfs.Authorizer
	userSource    UserSource
	sshConfig     *ssh.ServerConfig
	version       string

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{} // raw connections, tracked from accept time
	stopping bool
	wg       sync.WaitGroup

	status.ConnMetrics
}

// New creates a new SFTP server. The host key is loaded (or generated)
// eagerly so that a bad key configuration fails at startup rather than on
// first connection. userSource enables public-key authentication against
// each player's uploaded authorized_keys file; pass nil for password-only.
func New(config *Config, authorizer vfs.Authorizer, authenticator Authenticator, userSource UserSource, version string) (*Server, error) {
	if _, err := os.Stat(config.RootDir); err != nil {
		return nil, fmt.Errorf("root directory does not exist: %w", err)
	}
	if config.HostKeyFile == "" {
		return nil, fmt.Errorf("host key file path is required")
	}

	signer, err := loadOrGenerateHostKey(config.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading host key: %w", err)
	}

	s := &Server{
		config:        config,
		authenticator: authenticator,
		authorizer:    authorizer,
		userSource:    userSource,
		version:       version,
		conns:         make(map[net.Conn]struct{}),
	}
	s.SetStartTime(time.Now())

	sshConfig := &ssh.ServerConfig{
		MaxAuthTries:     6,
		ServerVersion:    "SSH-2.0-VikingSFTP",
		PasswordCallback: s.passwordCallback,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			logging.App.Debug("SSH auth attempt", "user", conn.User(), "method", method, "success", err == nil)
		},
	}
	// Public-key auth needs a character lookup and a home directory to find
	// the player's authorized_keys in; without both, the publickey method is
	// simply never advertised to clients.
	if userSource != nil && config.HomePattern != "" {
		sshConfig.PublicKeyCallback = s.publicKeyCallback
	}
	sshConfig.AddHostKey(signer)
	s.sshConfig = sshConfig

	return s, nil
}

// passwordCallback authenticates SSH password attempts. Timing-attack and
// user-enumeration protection lives inside Authenticate; the returned error
// is generic so nothing extra leaks to the client.
func (s *Server) passwordCallback(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	_, err := s.authenticator.Authenticate(conn.User(), string(pass))
	if err != nil {
		logging.Access.LogAuth("login", conn.User(), "failed", "error", err, "client_ip", conn.RemoteAddr().String(), "protocol", "sftp")
		return nil, fmt.Errorf("authentication failed")
	}

	logging.Access.LogAuth("login", conn.User(), "success", "client_ip", conn.RemoteAddr().String(), "protocol", "sftp")
	return nil, nil
}

// ListenAndServe starts the server and blocks until Stop is called or the
// listener fails.
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddr, s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		listener.Close()
		return nil
	}
	s.listener = listener
	s.mu.Unlock()

	logging.App.Info("SFTP server listening", "addr", listener.Addr().String())

	var tempDelay time.Duration // backoff for transient accept errors
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			stopping := s.stopping
			s.mu.Unlock()
			if stopping {
				return nil
			}
			// Transient errors (e.g. fd exhaustion) must not take the whole
			// daemon down; back off and retry, like net/http.Server.Serve.
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				logging.App.Warn("SFTP accept error, retrying", "error", err, "delay", tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return fmt.Errorf("accepting connection: %w", err)
		}
		tempDelay = 0

		// Register the raw connection before spawning, under the same lock
		// Stop uses, so a connection accepted concurrently with Stop is either
		// tracked (and closed by Stop) or refused here — never orphaned.
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			conn.Close()
			return nil
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go s.handleConn(conn)
	}
}

// Stop closes the listener and all active connections, then waits for
// connection and session goroutines to finish. Closing the raw connection
// unblocks clients stuck mid-handshake as well as established sessions.
func (s *Server) Stop() error {
	s.mu.Lock()
	s.stopping = true
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var err error
	if listener != nil {
		err = listener.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	s.wg.Wait()
	return err
}

// Addr returns the listener address, or nil if the server is not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Connection metrics (GetActiveConnections, GetTotalConnections,
// GetStartTime) are promoted from the embedded status.ConnMetrics.

// untrackConn removes conn from the tracked set and closes it.
func (s *Server) untrackConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	conn.Close()
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.untrackConn(conn)
	remoteAddr := conn.RemoteAddr().String()

	// Atomic increment-then-check so concurrent dials can't both slip past a
	// load-then-add limit check.
	n := s.IncActive()
	defer s.DecActive()
	if s.config.MaxConnections > 0 && n > int32(s.config.MaxConnections) {
		logging.App.Warn("Refusing SFTP connection: connection limit reached", "client_ip", remoteAddr, "max_connections", s.config.MaxConnections)
		return
	}

	s.IncTotal()
	logging.Access.LogAccess("connect", "", remoteAddr, "success", "protocol", "sftp")
	defer logging.Access.LogAccess("disconnect", "", remoteAddr, "success", "protocol", "sftp")

	tconn := &timeoutConn{Conn: conn, idle: s.config.IdleTimeout}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	sconn, chans, reqs, err := ssh.NewServerConn(tconn, s.sshConfig)
	if err != nil {
		// Failed handshakes/auth are already logged by the auth callback
		return
	}
	tconn.activate()
	defer sconn.Close()

	// Public-key logins are logged here rather than in the auth callback:
	// the callback fires before (and without) signature verification, so
	// only a completed handshake proves the client holds the private key.
	if sconn.Permissions != nil {
		if fp := sconn.Permissions.Extensions[permPubKeyFingerprint]; fp != "" {
			logging.Access.LogAuth("login", sconn.User(), "success", "method", "publickey", "fingerprint", fp, "client_ip", remoteAddr, "protocol", "sftp")
		}
	}

	go ssh.DiscardRequests(reqs)
	s.handleChannels(sconn, chans)
}

// handleChannels accepts session channels and rejects everything else
// (direct-tcpip forwarding, x11, agent, ...).
func (s *Server) handleChannels(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		// Track session goroutines so Stop waits for in-flight transfers and
		// their log lines to drain, not just the connection goroutine.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(sconn.User(), channel, requests)
		}()
	}
}

// handleSession services a session channel: only the sftp subsystem is
// granted. Shell, exec (scp), pty-req, and everything else are refused, so
// authenticated users can never obtain a shell.
func (s *Server) handleSession(user string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		if req.Type == "subsystem" && subsystemName(req.Payload) == "sftp" {
			req.Reply(true, nil)
			go func() {
				for r := range requests {
					r.Reply(false, nil)
				}
			}()
			s.serveSFTP(user, channel)
			return
		}
		req.Reply(false, nil)
	}
}

// subsystemName extracts the subsystem name from an SSH request payload
// (a length-prefixed string).
func subsystemName(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := binary.BigEndian.Uint32(payload)
	if uint32(len(payload)-4) < length {
		return ""
	}
	return string(payload[4 : 4+length])
}

// serveSFTP runs an SFTP request server over the channel, jailed to RootDir
// and starting in the user's home directory (mirroring the FTP driver).
func (s *Server) serveSFTP(user string, channel ssh.Channel) {
	home := vfs.ResolveHome(s.config.RootDir, s.config.HomePattern, user)
	fs := vfs.New(s.config.RootDir, user, s.authorizer, "sftp")

	server := sftp.NewRequestServer(channel, newHandlers(fs), sftp.WithStartDirectory(home))
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		logging.App.Debug("SFTP session ended", "user", user, "error", err)
	}
	server.Close()
}

// timeoutConn enforces the handshake deadline until activate is called, then
// pushes an idle deadline forward on every read/write.
type timeoutConn struct {
	net.Conn
	idle   time.Duration
	active atomic.Bool
}

func (c *timeoutConn) touch() {
	if c.active.Load() && c.idle > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	c.touch()
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	c.touch()
	return c.Conn.Write(b)
}

// activate switches from the handshake deadline to idle-timeout mode. The
// deadline is reset immediately so a read blocked since the handshake picks
// up the new deadline too.
func (c *timeoutConn) activate() {
	c.active.Store(true)
	if c.idle > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idle))
	} else {
		c.Conn.SetDeadline(time.Time{})
	}
}
