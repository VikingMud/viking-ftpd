package ftpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	ListenAddr    string // Address to listen on
	Port          int    // Port to listen on
	RootDir       string // Root directory that FTP users will be restricted to
	HomePattern   string // Pattern for user home directories (e.g., "/home/%s")
	TLSCertFile   string // Path to TLS certificate file
	TLSKeyFile    string // Path to TLS private key file
	PasvPortRange [2]int // Range of ports for passive mode transfers
	PasvAddress   string // Public IP for passive mode connections
	PasvIPVerify  bool   // Whether to verify data connection IPs
	IdleTimeout   int    // Connection idle timeout in seconds (0 = library default)
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
		ListenAddr: fmt.Sprintf("%s:%d", d.server.config.ListenAddr, d.server.config.Port),
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
	// Increment active connection counter
	d.server.activeConnections.Add(1)
	// Increment total connection counter
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

// GetFS returns the filesystem
// Interface: ftpserverlib.ClientDriver
func (c *ftpClient) GetFS() afero.Fs {
	return c
}

// ChangeCwd implements directory change
// Interface: ftpserverlib.ClientDriver
func (c *ftpClient) ChangeCwd(path string) error {
	if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("chdir", c.user, path, "denied")
		return os.ErrPermission
	}
	logging.Access.LogAccess("chdir", c.user, path, "success")
	return nil
}

// ReadDir is required for directory listing
// Interface: ftpserverlib.ClientDriver
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

// DeleteFile implements file deletion
// Interface: ftpserverlib.ClientDriver
func (c *ftpClient) DeleteFile(name string) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("remove", c.user, name, "denied", "error", err)
		return os.ErrPermission
	}

	if err := c.fs.Remove(path); err != nil {
		logging.Access.LogAccess("remove", c.user, name, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("remove", c.user, name, "success")
	return nil
}

// MakeDirectory implements directory creation
// Interface: ftpserverlib.ClientDriver
func (c *ftpClient) MakeDirectory(name string) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		logging.Access.LogAccess("mkdir", c.user, path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.Mkdir(path, 0755); err != nil {
		logging.Access.LogAccess("mkdir", c.user, path, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("mkdir", c.user, path, "success")
	return nil
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
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		if !c.server.authorizer.CanWrite(c.user, path) {
			logging.Access.LogAccess("open", c.user, path, "denied", "error", os.ErrPermission)
			return nil, os.ErrPermission
		}
		logging.Access.LogAccess("open", c.user, path, "success", "mode", "write")
	} else if !c.server.authorizer.CanRead(c.user, path) {
		logging.Access.LogAccess("open", c.user, path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	file, err := c.fs.OpenFile(path, flag, perm)
	if err != nil {
		if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
			logging.Access.LogAccess("open", c.user, path, "error", "mode", "write")
		} else {
			logging.Access.LogAccess("open", c.user, path, "error", "mode", "read")
		}
		return nil, err
	}

	// Only log size for read operations
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) == 0 {
		if fi, err := file.Stat(); err == nil {
			logging.Access.LogAccess("open", c.user, path, "success", "size", fi.Size())
		} else {
			logging.Access.LogAccess("open", c.user, path, "success", "size", 0)
		}
	}
	return file, nil
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

	file, err := c.fs.Create(path)
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
	err = c.fs.MkdirAll(resolvedPath, perm)
	logging.Access.LogAccess("mkdir", c.user, resolvedPath, "success", "mode", "write")
	return err
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
		logging.Access.LogAccess("rename", c.user, oldPath, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}

	if err := c.fs.Rename(oldPath, newPath); err != nil {
		logging.Access.LogAccess("rename", c.user, oldPath, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("rename", c.user, oldPath, "success", "mode", "write")
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
		return os.ErrPermission
	}
	return c.fs.Chmod(path, mode)
}

// Chown changes file owner
// Interface: afero.Fs
func (c *ftpClient) Chown(name string, uid, gid int) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		return os.ErrPermission
	}
	return c.fs.Chown(path, uid, gid)
}

// Chtimes changes file times
// Interface: afero.Fs
func (c *ftpClient) Chtimes(name string, atime time.Time, mtime time.Time) error {
	path, err := c.resolvePath(name)
	if err != nil {
		return err
	}

	if !c.server.authorizer.CanWrite(c.user, path) {
		return os.ErrPermission
	}
	return c.fs.Chtimes(path, atime, mtime)
}
