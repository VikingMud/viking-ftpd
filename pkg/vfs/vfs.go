// Package vfs provides an authorized, jailed filesystem shared by the FTP and
// SFTP servers. It is the single place where the access-control policy lives:
// which operations require read versus write permission, that rename needs
// write on both paths, that denials map to os.ErrPermission, that uploaded
// files get restricted permissions, and the access-log vocabulary. Both
// protocol servers construct one FS per authenticated session and delegate
// every filesystem operation to it, so the security policy cannot drift
// between them.
//
// All paths passed to an FS are absolute virtual paths (e.g. "/players/foo/x"),
// which serve as both the authorization path (relative to the MUD root) and
// the path inside the jail. Callers that work with client-relative paths (the
// FTP server has a per-session working directory) must resolve them to
// absolute form first.
package vfs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/afero"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
)

// ResolveHome returns the initial directory for a session: the absolute
// virtual path of the home_pattern directory for user if it exists and is a
// directory, otherwise "/". Both servers use this so home-directory behavior
// stays identical.
func ResolveHome(rootDir, pattern, user string) string {
	if pattern == "" {
		return "/"
	}
	homePath := filepath.Clean(fmt.Sprintf(pattern, user))
	jail := afero.NewBasePathFs(afero.NewOsFs(), rootDir)
	if info, err := jail.Stat(homePath); err == nil && info.IsDir() {
		return filepath.Join("/", homePath)
	}
	return "/"
}

// Authorizer answers per-path permission checks. Satisfied by
// *authorization.Authorizer.
type Authorizer interface {
	CanRead(username, path string) bool
	CanWrite(username, path string) bool
}

// FS is a per-session authorized view of the jailed filesystem.
type FS struct {
	fs       afero.Fs
	user     string
	authz    Authorizer
	protocol string // tags access-log lines, e.g. "ftp" or "sftp"
}

// New returns an FS jailed to rootDir for the given user. protocol is recorded
// on every access-log line so operators can attribute activity per protocol.
func New(rootDir, user string, authz Authorizer, protocol string) *FS {
	return &FS{
		fs:       afero.NewBasePathFs(afero.NewOsFs(), rootDir),
		user:     user,
		authz:    authz,
		protocol: protocol,
	}
}

// User returns the session's username.
func (f *FS) User() string { return f.user }

// log emits an access-log line tagged with the session protocol.
func (f *FS) log(op, path, status string, kv ...interface{}) {
	kv = append(kv, "protocol", f.protocol)
	logging.Access.LogAccess(op, f.user, path, status, kv...)
}

// isWriteFlag reports whether an OpenFile flag set implies modification.
func isWriteFlag(flag int) bool {
	return flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0
}

// clampPerm restricts file-creation permissions. Callers (and ftpserverlib)
// may pass os.ModePerm (0777); without clamping, uploaded files would be
// world-writable under a permissive umask.
func clampPerm(perm os.FileMode) os.FileMode {
	return perm & 0644
}

// Stat returns file info if the user may read the path.
func (f *FS) Stat(path string) (os.FileInfo, error) {
	if !f.authz.CanRead(f.user, path) {
		f.log("stat", path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}
	return f.fs.Stat(path)
}

// Open opens a file for reading.
func (f *FS) Open(path string) (afero.File, error) {
	if !f.authz.CanRead(f.user, path) {
		f.log("open", path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}
	file, err := f.fs.Open(path)
	if err != nil {
		f.log("open", path, "error", "error", err)
		return nil, err
	}
	if fi, statErr := file.Stat(); statErr == nil {
		f.log("open", path, "success", "size", fi.Size())
	} else {
		f.log("open", path, "success", "size", 0)
	}
	return file, nil
}

// OpenFile opens a file with the given flags, checking read or write
// permission according to the flags. Creation permissions are clamped.
func (f *FS) OpenFile(path string, flag int, perm os.FileMode) (afero.File, error) {
	writing := isWriteFlag(flag)
	if writing {
		if !f.authz.CanWrite(f.user, path) {
			f.log("open", path, "denied", "error", os.ErrPermission)
			return nil, os.ErrPermission
		}
	} else if !f.authz.CanRead(f.user, path) {
		f.log("open", path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	file, err := f.fs.OpenFile(path, flag, clampPerm(perm))
	if err != nil {
		if writing {
			f.log("open", path, "error", "mode", "write")
		} else {
			f.log("open", path, "error", "mode", "read")
		}
		return nil, err
	}

	if writing {
		f.log("open", path, "success", "mode", "write")
	} else if fi, statErr := file.Stat(); statErr == nil {
		f.log("open", path, "success", "size", fi.Size())
	} else {
		f.log("open", path, "success", "size", 0)
	}
	return file, nil
}

// Create creates or truncates a file for writing, with clamped permissions.
func (f *FS) Create(path string) (afero.File, error) {
	if !f.authz.CanWrite(f.user, path) {
		f.log("create", path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}
	file, err := f.fs.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, clampPerm(os.ModePerm))
	if err != nil {
		f.log("create", path, "error", "error", err)
		return nil, err
	}
	f.log("create", path, "success", "mode", "write")
	return file, nil
}

// ReadDirSorted lists a directory (sorted by name) if the user may read it.
func (f *FS) ReadDirSorted(path string) ([]os.FileInfo, error) {
	if !f.authz.CanRead(f.user, path) {
		f.log("readdir", path, "denied", "error", os.ErrPermission)
		return nil, os.ErrPermission
	}

	file, err := f.fs.Open(path)
	if err != nil {
		f.log("readdir", path, "error", "error", err)
		return nil, err
	}
	defer file.Close()

	entries, err := file.Readdir(-1)
	if err != nil {
		f.log("readdir", path, "error", "error", err)
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	f.log("readdir", path, "success", "count", len(entries))
	return entries, nil
}

// Mkdir creates a directory if the user may write the path.
func (f *FS) Mkdir(path string, perm os.FileMode) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("mkdir", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.Mkdir(path, perm); err != nil {
		f.log("mkdir", path, "error", "error", err)
		return err
	}
	f.log("mkdir", path, "success", "mode", "write")
	return nil
}

// MkdirAll creates a directory and any missing parents.
func (f *FS) MkdirAll(path string, perm os.FileMode) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("mkdir", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.MkdirAll(path, perm); err != nil {
		f.log("mkdir", path, "error", "error", err)
		return err
	}
	f.log("mkdir", path, "success", "mode", "write")
	return nil
}

// Remove deletes a file or empty directory.
func (f *FS) Remove(path string) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("remove", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.Remove(path); err != nil {
		f.log("remove", path, "error", "error", err)
		return err
	}
	f.log("remove", path, "success", "mode", "write")
	return nil
}

// RemoveAll deletes a path and any children it contains.
func (f *FS) RemoveAll(path string) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("remove", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.RemoveAll(path); err != nil {
		f.log("remove", path, "error", "error", err)
		return err
	}
	f.log("remove", path, "success", "mode", "write")
	return nil
}

// Rename moves a path, requiring write permission on both source and target.
func (f *FS) Rename(oldPath, newPath string) error {
	if !f.authz.CanWrite(f.user, oldPath) || !f.authz.CanWrite(f.user, newPath) {
		f.log("rename", oldPath, "denied", "error", os.ErrPermission, "to", newPath)
		return os.ErrPermission
	}
	if err := f.fs.Rename(oldPath, newPath); err != nil {
		f.log("rename", oldPath, "error", "error", err, "to", newPath)
		return err
	}
	f.log("rename", oldPath, "success", "mode", "write", "to", newPath)
	return nil
}

// Chmod changes a file's mode.
func (f *FS) Chmod(path string, mode os.FileMode) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("chmod", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.Chmod(path, mode); err != nil {
		f.log("chmod", path, "error", "error", err)
		return err
	}
	f.log("chmod", path, "success", "mode", "write")
	return nil
}

// Chown changes a file's owner.
func (f *FS) Chown(path string, uid, gid int) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("chown", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.Chown(path, uid, gid); err != nil {
		f.log("chown", path, "error", "error", err)
		return err
	}
	f.log("chown", path, "success", "mode", "write")
	return nil
}

// Chtimes changes a file's access and modification times.
func (f *FS) Chtimes(path string, atime, mtime time.Time) error {
	if !f.authz.CanWrite(f.user, path) {
		f.log("chtimes", path, "denied", "error", os.ErrPermission)
		return os.ErrPermission
	}
	if err := f.fs.Chtimes(path, atime, mtime); err != nil {
		f.log("chtimes", path, "error", "error", err)
		return err
	}
	f.log("chtimes", path, "success", "mode", "write")
	return nil
}
