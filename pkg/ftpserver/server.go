package ftpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	ftpserverlib "github.com/fclairamb/ftpserverlib"
	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/mmcdole/viking-ftpd/pkg/status"
	"github.com/mmcdole/viking-ftpd/pkg/users"
	"github.com/mmcdole/viking-ftpd/pkg/vfs"
	"github.com/spf13/afero"
)

// Authenticator verifies user credentials. Satisfied by
// *authentication.Authenticator.
type Authenticator interface {
	Authenticate(username, password string) (*users.User, error)
}

// Config holds the server configuration
type Config struct {
	ListenAddr     string        // Address to listen on
	Port           int           // Port to listen on
	RootDir        string        // Root directory that FTP users will be restricted to
	HomePattern    string        // Pattern for user home directories (e.g., "/home/%s")
	TLSCertFile    string        // Path to TLS certificate file
	TLSKeyFile     string        // Path to TLS private key file
	PasvPortRange  [2]int        // Range of ports for passive mode transfers
	PasvAddress    string        // Public IP for passive mode connections
	PasvIPVerify   bool          // Whether to verify data connection IPs
	IdleTimeout    time.Duration // Connection idle timeout (0 = library default)
	MaxConnections int           // Maximum concurrent connections (0 = unlimited)

	// Listener, if set, is used instead of binding ListenAddr:Port. Useful for
	// socket activation and tests that need an already-bound ephemeral port.
	Listener net.Listener
}

// Server wraps the FTP server with our custom auth
type Server struct {
	config        *Config
	authenticator Authenticator
	authorizer    vfs.Authorizer
	server        *ftpserverlib.FtpServer
	version       string

	status.ConnMetrics
}

// New creates a new FTP server
func New(config *Config, authorizer vfs.Authorizer, authenticator Authenticator, version string) (*Server, error) {
	// Validate config
	if _, err := os.Stat(config.RootDir); err != nil {
		return nil, fmt.Errorf("root directory does not exist: %w", err)
	}

	s := &Server{
		config:        config,
		authorizer:    authorizer,
		authenticator: authenticator,
		version:       version,
	}
	s.SetStartTime(time.Now())

	driver := &ftpDriver{server: s}
	s.server = ftpserverlib.NewFtpServer(driver)

	// Set our AppLogger as the FTP server's logger
	s.server.Logger = logging.App

	return s, nil
}

// ListenAndServe starts the server
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// Stop stops the server
func (s *Server) Stop() error {
	return s.server.Stop()
}

// Connection metrics (GetActiveConnections, GetTotalConnections,
// GetStartTime) are promoted from the embedded status.ConnMetrics.

// ftpDriver implements ftpserverlib.MainDriver
type ftpDriver struct {
	server *Server
}

var errNoTLS = errors.New("TLS is not configured")

// GetSettings returns server settings
// Interface: ftpserverlib.MainDriver
func (d *ftpDriver) GetSettings() (*ftpserverlib.Settings, error) {
	settings := &ftpserverlib.Settings{
		ListenAddr: net.JoinHostPort(d.server.config.ListenAddr, strconv.Itoa(d.server.config.Port)),
		PassiveTransferPortRange: &ftpserverlib.PortRange{
			Start: d.server.config.PasvPortRange[0],
			End:   d.server.config.PasvPortRange[1],
		},
		TLSRequired:       ftpserverlib.ClearOrEncrypted,
		DisableActiveMode: true,
		// ftpserverlib expects whole seconds.
		IdleTimeout: int(d.server.config.IdleTimeout / time.Second),
		Listener:    d.server.config.Listener,
	}

	if d.server.config.PasvAddress != "" {
		settings.PublicHost = d.server.config.PasvAddress
	}

	if d.server.config.PasvIPVerify {
		settings.PasvConnectionsCheck = ftpserverlib.IPMatchRequired
	} else {
		settings.PasvConnectionsCheck = ftpserverlib.IPMatchDisabled
	}

	return settings, nil
}

// ClientConnected is called when a client connects
// Interface: ftpserverlib.MainDriver
func (d *ftpDriver) ClientConnected(cc ftpserverlib.ClientContext) (string, error) {
	// Increment active connection counter. On refusal we leave it incremented:
	// ftpserverlib still calls ClientDisconnected (via a deferred end()) even
	// when ClientConnected returns an error, so the decrement there balances it.
	active := d.server.IncActive()
	if max := d.server.config.MaxConnections; max > 0 && active > int32(max) {
		logging.Access.LogAccess("connect", "", cc.RemoteAddr().String(), "denied", "error", "connection limit reached")
		return "Too many connections, please try again later", fmt.Errorf("connection limit reached")
	}

	// Only count accepted connections toward the lifetime total.
	d.server.IncTotal()

	// Enable debug logging if log level is debug
	if logging.App.IsDebug() {
		cc.SetDebug(true)
	}
	logging.Access.LogAccess("connect", "", cc.RemoteAddr().String(), "success")
	return fmt.Sprintf("Welcome to Viking FTP server (%s)", d.server.version), nil
}

// ClientDisconnected is called when a client disconnects
// Interface: ftpserverlib.MainDriver
func (d *ftpDriver) ClientDisconnected(cc ftpserverlib.ClientContext) {
	// Decrement active connection counter
	d.server.DecActive()

	logging.Access.LogAccess("disconnect", "", cc.RemoteAddr().String(), "success")
}

// AuthUser authenticates the user and returns a ClientDriver
// Interface: ftpserverlib.MainDriver
func (d *ftpDriver) AuthUser(cc ftpserverlib.ClientContext, user, pass string) (ftpserverlib.ClientDriver, error) {
	// Authenticate user
	_, err := d.server.authenticator.Authenticate(user, pass)
	if err != nil {
		logging.Access.LogAuth("login", user, "failed", "error", err, "client_ip", cc.RemoteAddr().String())
		return nil, fmt.Errorf("authentication failed")
	}

	// Start the session in the user's home directory (or root if absent).
	cc.SetPath(vfs.ResolveHome(d.server.config.RootDir, d.server.config.HomePattern, user))
	cc.SetDebug(logging.App.IsDebug())

	logging.Access.LogAuth("login", user, "success", "client_ip", cc.RemoteAddr().String())
	return &ftpClient{
		fs: vfs.New(d.server.config.RootDir, user, d.server.authorizer, "ftp"),
		cc: cc,
	}, nil
}

// GetTLSConfig returns TLS config
// Interface: ftpserverlib.MainDriver
func (d *ftpDriver) GetTLSConfig() (*tls.Config, error) {
	if d.server.config.TLSCertFile == "" || d.server.config.TLSKeyFile == "" {
		// If no TLS config is provided, return error to indicate no TLS support
		return nil, errNoTLS
	}

	cert, err := tls.LoadX509KeyPair(d.server.config.TLSCertFile, d.server.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert/key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ftpClient implements ftpserverlib.ClientDriver (afero.Fs) by resolving
// client-relative paths against the session working directory and delegating
// every operation to the shared authorized filesystem, which owns the
// authorization policy, jail, and access logging.
type ftpClient struct {
	fs *vfs.FS
	cc ftpserverlib.ClientContext
}

// resolvePath converts an FTP protocol path to an absolute virtual path.
// Absolute paths are relative to the FTP root; relative paths are joined onto
// the current working directory.
func (c *ftpClient) resolvePath(name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Clean(filepath.Join(c.cc.Path(), name))
}

// ReadDir returns a directory listing.
// Interface: ftpserverlib.ClientDriverExtensionFileList
func (c *ftpClient) ReadDir(name string) ([]os.FileInfo, error) {
	return c.fs.ReadDirSorted(c.resolvePath(name))
}

// Open opens a file for reading.
// Interface: afero.Fs
func (c *ftpClient) Open(name string) (afero.File, error) {
	return c.fs.Open(c.resolvePath(name))
}

// OpenFile opens a file using the given flags and mode.
// Interface: afero.Fs
func (c *ftpClient) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return c.fs.OpenFile(c.resolvePath(name), flag, perm)
}

// Create creates a new file.
// Interface: afero.Fs
func (c *ftpClient) Create(name string) (afero.File, error) {
	return c.fs.Create(c.resolvePath(name))
}

// Mkdir creates a directory.
// Interface: afero.Fs
func (c *ftpClient) Mkdir(name string, perm os.FileMode) error {
	return c.fs.Mkdir(c.resolvePath(name), perm)
}

// MkdirAll creates a directory and all parent directories.
// Interface: afero.Fs
func (c *ftpClient) MkdirAll(path string, perm os.FileMode) error {
	return c.fs.MkdirAll(c.resolvePath(path), perm)
}

// Remove removes a file.
// Interface: afero.Fs
func (c *ftpClient) Remove(name string) error {
	return c.fs.Remove(c.resolvePath(name))
}

// RemoveAll removes a directory and all its contents.
// Interface: afero.Fs
func (c *ftpClient) RemoveAll(path string) error {
	return c.fs.RemoveAll(c.resolvePath(path))
}

// Rename renames a file, requiring write permission on both paths.
// Interface: afero.Fs
func (c *ftpClient) Rename(oldname, newname string) error {
	return c.fs.Rename(c.resolvePath(oldname), c.resolvePath(newname))
}

// Stat returns file info.
// Interface: afero.Fs
func (c *ftpClient) Stat(name string) (os.FileInfo, error) {
	return c.fs.Stat(c.resolvePath(name))
}

// Name returns the name of the filesystem.
// Interface: afero.Fs
func (c *ftpClient) Name() string {
	return "VikingFTPD"
}

// Chmod changes file mode.
// Interface: afero.Fs
func (c *ftpClient) Chmod(name string, mode os.FileMode) error {
	return c.fs.Chmod(c.resolvePath(name), mode)
}

// Chown changes file owner.
// Interface: afero.Fs
func (c *ftpClient) Chown(name string, uid, gid int) error {
	return c.fs.Chown(c.resolvePath(name), uid, gid)
}

// Chtimes changes file times.
// Interface: afero.Fs
func (c *ftpClient) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return c.fs.Chtimes(c.resolvePath(name), atime, mtime)
}
