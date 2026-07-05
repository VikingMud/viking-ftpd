package sftpserver

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/afero"

	"github.com/mmcdole/viking-ftpd/pkg/vfs"
)

// translateError maps a filesystem error to a generic SFTP status error.
// pkg/sftp sends the raw error text to the client, and afero's BasePathFs does
// not strip the real jail path from its errors, so returning fs errors
// verbatim would leak ftp_root_dir. The real error is logged inside vfs.
func translateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return sftp.ErrSSHFxNoSuchFile
	case errors.Is(err, os.ErrPermission):
		return sftp.ErrSSHFxPermissionDenied
	default:
		return sftp.ErrSSHFxFailure
	}
}

// sftpHandlers implements sftp.Handlers (FileReader, FileWriter, FileCmder,
// FileLister) by translating SFTP requests into calls on the shared authorized
// filesystem. The request server hands every operation an absolute virtual
// path, which is exactly what vfs expects. Authorization, jailing, and access
// logging all live in vfs; the handlers only do protocol translation.
type sftpHandlers struct {
	fs *vfs.FS
}

func newHandlers(fs *vfs.FS) sftp.Handlers {
	h := &sftpHandlers{fs: fs}
	return sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}
}

// Fileread handles downloads (Get)
// Interface: sftp.FileReader
func (h *sftpHandlers) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	file, err := h.fs.Open(r.Filepath)
	if err != nil {
		return nil, translateError(err)
	}
	return file, nil
}

// Filewrite handles uploads (Put)
// Interface: sftp.FileWriter
func (h *sftpHandlers) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return h.openForWrite(r)
}

// OpenFile handles read-write opens on a single handle
// Interface: sftp.OpenFileWriter
func (h *sftpHandlers) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return h.openForWrite(r)
}

func (h *sftpHandlers) openForWrite(r *sftp.Request) (afero.File, error) {
	file, err := h.fs.OpenFile(r.Filepath, toOsFileFlags(r.Pflags()), os.ModePerm)
	if err != nil {
		return nil, translateError(err)
	}
	return file, nil
}

// toOsFileFlags converts SFTP open flags to os.OpenFile flags. O_APPEND is
// deliberately never set: the request server writes with WriteAt offsets,
// which conflict with append-mode files. An Append open is treated as write
// intent so it doesn't fall through to O_RDONLY (clients that resume uploads
// then write at explicit offsets, which is correct without O_APPEND).
func toOsFileFlags(p sftp.FileOpenFlags) int {
	var flags int
	switch {
	case p.Read && (p.Write || p.Append):
		flags = os.O_RDWR
	case p.Write || p.Append:
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
		return translateError(h.fs.Rename(r.Filepath, r.Target))
	case "Remove", "Rmdir":
		return translateError(h.fs.Remove(r.Filepath))
	case "Mkdir":
		return translateError(h.fs.Mkdir(r.Filepath, 0755))
	default:
		// Link and Symlink are never allowed: users must not create links
		// that could point outside their authorized subtrees.
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (h *sftpHandlers) setstat(r *sftp.Request) error {
	attrs := r.Attributes()
	flags := r.AttrFlags()

	if flags.Size {
		file, err := h.fs.OpenFile(r.Filepath, os.O_WRONLY, 0)
		if err != nil {
			return translateError(err)
		}
		err = file.Truncate(int64(attrs.Size))
		file.Close()
		if err != nil {
			return translateError(err)
		}
	}
	if flags.Permissions {
		if err := h.fs.Chmod(r.Filepath, os.FileMode(attrs.Mode)&os.ModePerm); err != nil {
			return translateError(err)
		}
	}
	if flags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if err := h.fs.Chtimes(r.Filepath, atime, mtime); err != nil {
			return translateError(err)
		}
	}
	// UID/GID changes are intentionally ignored: there is no legitimate use in
	// this authorization model, and honoring chown would be dangerous if the
	// daemon runs as root. Clients that request it still succeed for the other
	// attributes.
	return nil
}

// Filelist handles directory listings, stats, and readlink
// Interface: sftp.FileLister
func (h *sftpHandlers) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		entries, err := h.fs.ReadDirSorted(r.Filepath)
		if err != nil {
			return nil, translateError(err)
		}
		return listerAt(entries), nil

	case "Stat":
		fi, err := h.fs.Stat(r.Filepath)
		if err != nil {
			return nil, translateError(err)
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
