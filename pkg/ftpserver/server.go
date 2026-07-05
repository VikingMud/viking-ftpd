package ftpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	ftpserverlib "github.com/fclairamb/ftpserverlib"
	"github.com/mmcdole/viking-ftpd/pkg/authentication"
	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/spf13/afero"
)

// Config holds the server configuration
type Config struct {
	ListenAddr     string // Address to listen on
	Port           int    // Port to listen on
	RootDir        string // Root directory that FTP users will be restricted to
	HomePattern    string // Pattern for user home directories (e.g., "/home/%s")
	TLSCertFile    string // Path to TLS certificate file
	TLSKeyFile     string // Path to TLS private key file
	PasvPortRange  [2]int // Range of ports for passive mode transfers
	PasvAddress    string // Public IP for passive mode connections
	PasvIPVerify   bool   // Whether to verify data connection IPs
	IdleTimeout    int    // Connection idle timeout in seconds (0 = library default)
	MaxConnections int    // Maximum concurrent connections (0 = unlimited)
}

// Server wraps the FTP server with our custom auth
type Server struct {
	config            *Config
	authenticator     *authentication.Authenticator
	authorizer        *authorization.Authorizer
	server            *ftpserverlib.FtpServer
	version           string
	activeConnections atomic.Int32
	totalConnections  atomic.Int64
	startTime         time.Time
}

// New creates a new FTP server
func New(config *Config, authorizer *authorization.Authorizer, authenticator *authentication.Authenticator, version string) (*Server, error) {
	// Validate config
	if _, err := os.Stat(config.RootDir); err != nil {
		return nil, fmt.Errorf("root directory does not exist: %w", err)
	}

	s := &Server{
		config:        config,
		authorizer:    authorizer,
		authenticator: authenticator,
		version:       version,
		startTime:     time.Now(),
	}

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

// GetActiveConnections returns the current number of active connections
func (s *Server) GetActiveConnections() int32 {
	return s.activeConnections.Load()
}

// GetTotalConnections returns the total number of connections since server start
func (s *Server) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetStartTime returns the server start time
func (s *Server) GetStartTime() time.Time {
	return s.startTime
}

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
		IdleTimeout:       d.server.config.IdleTimeout,
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
	active := d.server.activeConnections.Add(1)
	if max := d.server.config.MaxConnections; max > 0 && active > int32(max) {
		logging.Access.LogAccess("connect", "", cc.RemoteAddr().String(), "denied", "error", "connection limit reached")
		return "Too many connections, please try again later", fmt.Errorf("connection limit reached")
	}

	// Only count accepted connections toward the lifetime total.
	d.server.totalConnections.Add(1)

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
	d.server.activeConnections.Add(-1)

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

	// Create filesystem with root already handled
	fs := afero.NewBasePathFs(afero.NewOsFs(), d.server.config.RootDir)

	// Set home directory if pattern is configured and directory exists
	var homePath string
	if d.server.config.HomePattern != "" {
		homePath = filepath.Clean(fmt.Sprintf(d.server.config.HomePattern, user))
		if info, err := fs.Stat(homePath); err != nil || !info.IsDir() {
			homePath = "" // Fall back to root if home doesn't exist or isn't a directory
		}
	}

	// Set initial path (home or root)
	cc.SetPath(filepath.Join("/", homePath))

	cc.SetDebug(logging.App.IsDebug())

	logging.Access.LogAuth("login", user, "success", "client_ip", cc.RemoteAddr().String())
	return &ftpClient{
		server:   d.server,
		user:     user,
		homePath: homePath,
		rootPath: d.server.config.RootDir,
		fs:       fs,
		cc:       cc,
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

// ftpClient implements ftpserverlib.ClientDriver and afero.Fs
type ftpClient struct {
	server   *Server
	user     string
	fs       afero.Fs
	homePath string                     // User's home directory path (relative to root)
	rootPath string                     // Server's root directory absolute path
	cc       ftpserverlib.ClientContext // Current client context
}

// resolvePath converts FTP protocol paths to filesystem paths
func (c *ftpClient) resolvePath(name string) (string, error) {
	// If path is absolute, it's relative to root
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}

	// Otherwise, it's relative to current directory
	currentPath := c.cc.Path()
	return filepath.Clean(filepath.Join(currentPath, name)), nil
}

// ReadDir returns a directory listing.
// Interface: ftpserverlib.ClientDriverExtensionFileList
func (c *ftpClient) ReadDir(name string) ([]os.FileInfo, error) {
	path, err := c.resolvePath(name)
	if err != nil {
		return nil, err
	}

	if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("readdir", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	f, err := c.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	readDirIface, ok := f.(interface {
		Readdir(count int) ([]os.FileInfo, error)
	})
	if !ok {
		return nil, fmt.Errorf("file does not support directory listing")
	}

	entries, err := readDirIface.Readdir(-1)
	if err != nil {
		return nil, err
	}

	// Sort entries alphabetically by name
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	logging.Access.LogAccess("readdir", c.user, path, "success", "count", len(entries))
	return entries, nil
}

// Open opens a file for reading
// Interface: afero.Fs
func (c *ftpClient) Open(name string) (afero.File, error) {
	path, err := c.resolvePath(name)
	if err != nil {
		return nil, err
	}

	if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("open", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	file, err := c.fs.Open(path)
	if err != nil {
		logging.Access.LogAccess("open", c.user, path, "error", "error", err)
		return nil, err
	}

	// Get file size for logging
	if fi, err := file.Stat(); err == nil {
		logging.Access.LogAccess("open", c.user, path, "success", "size", fi.Size())
	} else {
		logging.Access.LogAccess("open", c.user, path, "success", "size", 0)
	}
	return file, nil
}

// OpenFile opens a file using the given flags and mode
// Interface: afero.Fs
func (c *ftpClient) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	path, err := c.resolvePath(name)
	if err != nil {
		return nil, err
	}

	// Check write permission if file is being created or modified
	writing := flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0
	if writing {
		if !c.server.authorizer.CanWrite(c.user, path) {
			logging.Access.LogAccess("open", c.user, path, "denied", "error", os.ErrPermission)
			return nil, os.ErrPermission
		}
	} else if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("open", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	file, err := c.fs.OpenFile(path, flag, clampPerm(perm))
	if err != nil {
		if writing {
			logging.Access.LogAccess("open", c.user, path, "error", "mode", "write")
		} else {
			logging.Access.LogAccess("open", c.user, path, "error", "mode", "read")
		}
		return nil, err
	}

	if writing {
		logging.Access.LogAccess("open", c.user, path, "success", "mode", "write")
	} else if fi, err := file.Stat(); err == nil {
		logging.Access.LogAccess("open", c.user, path, "success", "size", fi.Size())
	} else {
		logging.Access.LogAccess("open", c.user, path, "success", "size", 0)
	}
	return file, nil
}

// clampPerm restricts file-creation permissions. ftpserverlib passes
// os.ModePerm (0777) for uploads; without clamping, uploaded files land at
// 0777&^umask, which is world-writable under a permissive umask.
func clampPerm(perm os.FileMode) os.FileMode {
	return perm & 0644
}

// Create creates a new file
// Interface: afero.Fs
func (c *ftpClient) Create(name string) (afero.File, error) {
	path, err := c.resolvePath(name)
	if err != nil {
		return nil, err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("create", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	// afero's Create uses 0666; open explicitly so uploads get clamped perms.
	file, err := c.fs.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, clampPerm(os.ModePerm))
	if err != nil {
		logging.Access.LogAccess("create", c.user, path, "error", "error", err)
		return nil, err
	}

	logging.Access.LogAccess("create", c.user, path, "success", "mode", "write")
	return file, nil
}

// Mkdir creates a directory
// Interface: afero.Fs
func (c *ftpClient) Mkdir(name string, perm os.FileMode) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("mkdir", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.Mkdir(path, perm); err != nil {
		logging.Access.LogAccess("mkdir", c.user, path, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("mkdir", c.user, path, "success", "mode", "write")
	return nil
}

// MkdirAll creates a directory and all parent directories
// Interface: afero.Fs
func (c *ftpClient) MkdirAll(path string, perm os.FileMode) error {
	resolvedPath, err := c.resolvePath(path)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, resolvedPath) {
		logging.Access.LogAccess("mkdir", c.user, resolvedPath, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.MkdirAll(resolvedPath, perm); err != nil {
		logging.Access.LogAccess("mkdir", c.user, resolvedPath, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("mkdir", c.user, resolvedPath, "success", "mode", "write")
	return nil
}

// Remove removes a file
// Interface: afero.Fs
func (c *ftpClient) Remove(name string) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("remove", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.Remove(path); err != nil {
		logging.Access.LogAccess("remove", c.user, path, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("remove", c.user, path, "success", "mode", "write")
	return nil
}

// RemoveAll removes a directory and all its contents
// Interface: afero.Fs
func (c *ftpClient) RemoveAll(path string) error {
	resolvedPath, err := c.resolvePath(path)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, resolvedPath) {
		logging.Access.LogAccess("remove", c.user, resolvedPath, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.RemoveAll(resolvedPath); err != nil {
		logging.Access.LogAccess("remove", c.user, resolvedPath, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("remove", c.user, resolvedPath, "success", "mode", "write")
	return nil
}

// Rename renames a file
// Interface: afero.Fs
func (c *ftpClient) Rename(oldname, newname string) error {
	oldPath, err := c.resolvePath(oldname)
	if err != nil {
		return err
	}
	newPath, err := c.resolvePath(newname)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, oldPath) ||
		!c.server.authorizer.CanWrite(c.user, newPath) {
		logging.Access.LogAccess("rename", c.user, oldPath, "denied", "error", os.ErrPermission, "to", newPath)
		return os.ErrPermission
	}

	if err := c.fs.Rename(oldPath, newPath); err != nil {
		logging.Access.LogAccess("rename", c.user, oldPath, "error", "error", err, "to", newPath)
		return err
	}

	logging.Access.LogAccess("rename", c.user, oldPath, "success", "mode", "write", "to", newPath)
	return nil
}

// Stat returns file info
// Interface: afero.Fs
func (c *ftpClient) Stat(name string) (os.FileInfo, error) {
	path, err := c.resolvePath(name)
	if err != nil {
		return nil, err
	}

	if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("stat", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}
	return c.fs.Stat(path)
}

// Name returns the name of the filesystem
// Interface: afero.Fs
func (c *ftpClient) Name() string {
	return "VikingFTPD"
}

// Chmod changes file mode
// Interface: afero.Fs
func (c *ftpClient) Chmod(name string, mode os.FileMode) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("chmod", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := c.fs.Chmod(path, mode); err != nil {
		logging.Access.LogAccess("chmod", c.user, path, "error", "error", err)
		return err
	}
	logging.Access.LogAccess("chmod", c.user, path, "success", "mode", "write")
	return nil
}

// Chown changes file owner
// Interface: afero.Fs
func (c *ftpClient) Chown(name string, uid, gid int) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("chown", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := c.fs.Chown(path, uid, gid); err != nil {
		logging.Access.LogAccess("chown", c.user, path, "error", "error", err)
		return err
	}
	logging.Access.LogAccess("chown", c.user, path, "success", "mode", "write")
	return nil
}

// Chtimes changes file times
// Interface: afero.Fs
func (c *ftpClient) Chtimes(name string, atime time.Time, mtime time.Time) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("chtimes", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := c.fs.Chtimes(path, atime, mtime); err != nil {
		logging.Access.LogAccess("chtimes", c.user, path, "error", "error", err)
		return err
	}
	logging.Access.LogAccess("chtimes", c.user, path, "success", "mode", "write")
	return nil
}
