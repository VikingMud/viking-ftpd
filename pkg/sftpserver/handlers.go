package sftpserver

import (
	"io"
	"os"
	"sort"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/afero"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
)

// sftpHandlers implements sftp.Handlers (FileReader, FileWriter, FileCmder,
// FileLister). The request server hands every operation an absolute virtual
// path, which is both the authorization path (relative to the MUD root) and
// the filesystem path inside the BasePathFs jail — the same convention the
// FTP driver uses.
type sftpHandlers struct {
	server *Server
	user   string
	fs     afero.Fs
}

func newHandlers(server *Server, user string, fs afero.Fs) sftp.Handlers {
	h := &sftpHandlers{server: server, user: user, fs: fs}
	return sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}
}

// Fileread handles downloads (Get)
// Interface: sftp.FileReader
func (h *sftpHandlers) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path := r.Filepath
	if !h.server.authorizer.CanRead(h.user, path) {
		logging.Access.LogAccess("open", h.user, path, "denied", "error", os.ErrPermission)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	file, err := h.fs.Open(path)
	if err != nil {
		logging.Access.LogAccess("open", h.user, path, "error", "error", err)
		return nil, err
	}

	if fi, err := file.Stat(); err == nil {
		logging.Access.LogAccess("open", h.user, path, "success", "size", fi.Size())
	} else {
		logging.Access.LogAccess("open", h.user, path, "success", "size", 0)
	}
	return file, nil
}

// Filewrite handles uploads (Put)
// Interface: sftp.FileWriter
func (h *sftpHandlers) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	file, err := h.openForWrite(r)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// OpenFile handles read-write opens on a single handle
// Interface: sftp.OpenFileWriter
func (h *sftpHandlers) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	file, err := h.openForWrite(r)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (h *sftpHandlers) openForWrite(r *sftp.Request) (afero.File, error) {
	path := r.Filepath
	flags := r.Pflags()

	op := "open"
	if flags.Creat {
		op = "create"
	}

	if !h.server.authorizer.CanWrite(h.user, path) {
		logging.Access.LogAccess(op, h.user, path, "denied", "error", os.ErrPermission)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	file, err := h.fs.OpenFile(path, toOsFileFlags(flags), 0644)
	if err != nil {
		logging.Access.LogAccess(op, h.user, path, "error", "error", err)
		return nil, err
	}

	logging.Access.LogAccess(op, h.user, path, "success", "mode", "write")
	return file, nil
}

// toOsFileFlags converts SFTP open flags to os.OpenFile flags. O_APPEND is
// deliberately never set: the request server writes with WriteAt offsets,
// which conflict with append-mode files.
func toOsFileFlags(p sftp.FileOpenFlags) int {
	var flags int
	switch {
	case p.Read && p.Write:
		flags = os.O_RDWR
	case p.Write:
		flags = os.O_WRONLY
	default:
		flags = os.O_RDONLY
	}
	if p.Creat {
		flags |= os.O_CREATE
	}
	if p.Trunc {
		flags |= os.O_TRUNC
	}
	if p.Excl {
		flags |= os.O_EXCL
	}
	return flags
}

// Filecmd handles metadata and namespace operations
// Interface: sftp.FileCmder
func (h *sftpHandlers) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Setstat":
		return h.setstat(r)
	case "Rename", "PosixRename":
		return h.rename(r)
	case "Remove", "Rmdir":
		return h.remove(r)
	case "Mkdir":
		return h.mkdir(r)
	default:
		// Link and Symlink are never allowed: users must not create links
		// that could point outside their authorized subtrees.
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (h *sftpHandlers) setstat(r *sftp.Request) error {
	path := r.Filepath
	if !h.server.authorizer.CanWrite(h.user, path) {
		return sftp.ErrSSHFxPermissionDenied
	}

	attrs := r.Attributes()
	flags := r.AttrFlags()

	if flags.Size {
		file, err := h.fs.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		err = file.Truncate(int64(attrs.Size))
		file.Close()
		if err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := h.fs.Chmod(path, os.FileMode(attrs.Mode)&os.ModePerm); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if err := h.fs.Chtimes(path, atime, mtime); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := h.fs.Chown(path, int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	return nil
}

func (h *sftpHandlers) rename(r *sftp.Request) error {
	oldPath := r.Filepath
	newPath := r.Target

	if !h.server.authorizer.CanWrite(h.user, oldPath) ||
		!h.server.authorizer.CanWrite(h.user, newPath) {
		logging.Access.LogAccess("rename", h.user, oldPath, "denied", "error", os.ErrPermission)
		return sftp.ErrSSHFxPermissionDenied
	}

	if err := h.fs.Rename(oldPath, newPath); err != nil {
		logging.Access.LogAccess("rename", h.user, oldPath, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("rename", h.user, oldPath, "success", "mode", "write")
	return nil
}

func (h *sftpHandlers) remove(r *sftp.Request) error {
	path := r.Filepath
	if !h.server.authorizer.CanWrite(h.user, path) {
		logging.Access.LogAccess("remove", h.user, path, "denied", "error", os.ErrPermission)
		return sftp.ErrSSHFxPermissionDenied
	}

	if err := h.fs.Remove(path); err != nil {
		logging.Access.LogAccess("remove", h.user, path, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("remove", h.user, path, "success", "mode", "write")
	return nil
}

func (h *sftpHandlers) mkdir(r *sftp.Request) error {
	path := r.Filepath
	if !h.server.authorizer.CanWrite(h.user, path) {
		logging.Access.LogAccess("mkdir", h.user, path, "denied", "error", os.ErrPermission)
		return sftp.ErrSSHFxPermissionDenied
	}

	if err := h.fs.Mkdir(path, 0755); err != nil {
		logging.Access.LogAccess("mkdir", h.user, path, "error", "error", err)
		return err
	}

	logging.Access.LogAccess("mkdir", h.user, path, "success", "mode", "write")
	return nil
}

// Filelist handles directory listings, stats, and readlink
// Interface: sftp.FileLister
func (h *sftpHandlers) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path := r.Filepath

	switch r.Method {
	case "List":
		if !h.server.authorizer.CanRead(h.user, path) {
			logging.Access.LogAccess("readdir", h.user, path, "denied", "error", os.ErrPermission)
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		f, err := h.fs.Open(path)
		if err != nil {
			logging.Access.LogAccess("readdir", h.user, path, "error", "error", err)
			return nil, err
		}
		defer f.Close()

		entries, err := f.Readdir(-1)
		if err != nil {
			logging.Access.LogAccess("readdir", h.user, path, "error", "error", err)
			return nil, err
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})

		logging.Access.LogAccess("readdir", h.user, path, "success", "count", len(entries))
		return listerAt(entries), nil

	case "Stat":
		if !h.server.authorizer.CanRead(h.user, path) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		fi, err := h.fs.Stat(path)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil

	default:
		// Readlink: link targets are never revealed (the FTP server has no
		// link operations either).
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

// listerAt adapts a []os.FileInfo to the sftp.ListerAt interface
type listerAt []os.FileInfo

func (l listerAt) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}
