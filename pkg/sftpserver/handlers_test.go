package sftpserver

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

// SFTP open flag wire values (draft-ietf-secsh-filexfer)
const (
	flagRead  = 0x1
	flagWrite = 0x2
	flagCreat = 0x8
	flagTrunc = 0x10
)

type stubAccessSource struct {
	tree map[string]interface{}
}

func (s *stubAccessSource) LoadAccessData() (map[string]interface{}, error) {
	return s.tree, nil
}

// testTree gives everyone Read everywhere except /private, which is revoked.
// Write access comes only from the implicit GrantGrant on players/<self>.
func testTree() map[string]interface{} {
	return map[string]interface{}{
		"access_map": map[string]interface{}{
			"*": map[string]interface{}{
				".":       authorization.Read,
				"*":       authorization.Read,
				"private": authorization.Revoked,
			},
		},
	}
}

// newTestHandlers builds handlers for user "alice" over a real temp dir
// containing /hello.txt, /private/secret.txt, and /players/alice/note.txt.
func newTestHandlers(t *testing.T) (*sftpHandlers, string) {
	t.Helper()
	root := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(root, "private"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "players", "alice"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello world"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "private", "secret.txt"), []byte("secret"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "players", "alice", "note.txt"), []byte("note"), 0644))

	charSource := users.NewMemorySource()
	charSource.AddUser(&users.User{Username: "alice", Level: users.WIZARD})
	authorizer := authorization.NewAuthorizer(&stubAccessSource{testTree()}, charSource, time.Minute)

	server := &Server{
		config:     &Config{RootDir: root},
		authorizer: authorizer,
	}
	fs := afero.NewBasePathFs(afero.NewOsFs(), root)
	return &sftpHandlers{server: server, user: "alice", fs: fs}, root
}

func TestFileread(t *testing.T) {
	h, _ := newTestHandlers(t)

	t.Run("allowed", func(t *testing.T) {
		reader, err := h.Fileread(sftp.NewRequest("Get", "/hello.txt"))
		require.NoError(t, err)
		defer reader.(io.Closer).Close()

		buf := make([]byte, 11)
		n, err := reader.ReadAt(buf, 0)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(buf[:n]))
	})

	t.Run("denied", func(t *testing.T) {
		_, err := h.Fileread(sftp.NewRequest("Get", "/private/secret.txt"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	})
}

func TestFilewrite(t *testing.T) {
	h, root := newTestHandlers(t)

	t.Run("allowed in home", func(t *testing.T) {
		req := sftp.NewRequest("Put", "/players/alice/new.txt")
		req.Flags = flagWrite | flagCreat | flagTrunc

		writer, err := h.Filewrite(req)
		require.NoError(t, err)

		_, err = writer.WriteAt([]byte("uploaded"), 0)
		require.NoError(t, err)
		require.NoError(t, writer.(io.Closer).Close())

		data, err := os.ReadFile(filepath.Join(root, "players", "alice", "new.txt"))
		require.NoError(t, err)
		assert.Equal(t, "uploaded", string(data))
	})

	t.Run("denied outside home", func(t *testing.T) {
		req := sftp.NewRequest("Put", "/denied.txt")
		req.Flags = flagWrite | flagCreat | flagTrunc

		_, err := h.Filewrite(req)
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
		assert.NoFileExists(t, filepath.Join(root, "denied.txt"))
	})
}

func TestOpenFileReadWrite(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := sftp.NewRequest("Open", "/players/alice/note.txt")
	req.Flags = flagRead | flagWrite

	file, err := h.OpenFile(req)
	require.NoError(t, err)
	defer file.(io.Closer).Close()

	_, err = file.WriteAt([]byte("NOTE"), 0)
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = file.ReadAt(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, "NOTE", string(buf))
}

func TestFilecmdMkdirRemove(t *testing.T) {
	h, root := newTestHandlers(t)

	t.Run("mkdir allowed in home", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Mkdir", "/players/alice/subdir"))
		require.NoError(t, err)
		assert.DirExists(t, filepath.Join(root, "players", "alice", "subdir"))
	})

	t.Run("mkdir denied outside home", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Mkdir", "/newdir"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	})

	t.Run("remove allowed in home", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Remove", "/players/alice/note.txt"))
		require.NoError(t, err)
		assert.NoFileExists(t, filepath.Join(root, "players", "alice", "note.txt"))
	})

	t.Run("remove denied on read-only path", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Remove", "/hello.txt"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
		assert.FileExists(t, filepath.Join(root, "hello.txt"))
	})
}

func TestFilecmdRename(t *testing.T) {
	h, root := newTestHandlers(t)

	t.Run("allowed when both paths writable", func(t *testing.T) {
		req := sftp.NewRequest("Rename", "/players/alice/note.txt")
		req.Target = "/players/alice/renamed.txt"

		require.NoError(t, h.Filecmd(req))
		assert.FileExists(t, filepath.Join(root, "players", "alice", "renamed.txt"))
	})

	t.Run("denied when target not writable", func(t *testing.T) {
		req := sftp.NewRequest("Rename", "/players/alice/renamed.txt")
		req.Target = "/escaped.txt"

		assert.ErrorIs(t, h.Filecmd(req), sftp.ErrSSHFxPermissionDenied)
	})

	t.Run("denied when source not writable", func(t *testing.T) {
		req := sftp.NewRequest("Rename", "/hello.txt")
		req.Target = "/players/alice/stolen.txt"

		assert.ErrorIs(t, h.Filecmd(req), sftp.ErrSSHFxPermissionDenied)
	})
}

func TestFilecmdLinksUnsupported(t *testing.T) {
	h, _ := newTestHandlers(t)

	for _, method := range []string{"Symlink", "Link"} {
		req := sftp.NewRequest(method, "/players/alice/target")
		req.Target = "/players/alice/link"
		assert.ErrorIs(t, h.Filecmd(req), sftp.ErrSSHFxOpUnsupported, method)
	}
}

func TestFilecmdSetstat(t *testing.T) {
	h, _ := newTestHandlers(t)

	t.Run("denied outside home", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Setstat", "/hello.txt"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	})

	t.Run("allowed in home with no attributes", func(t *testing.T) {
		err := h.Filecmd(sftp.NewRequest("Setstat", "/players/alice/note.txt"))
		assert.NoError(t, err)
	})
}

func TestFilelist(t *testing.T) {
	h, _ := newTestHandlers(t)

	t.Run("list allowed and sorted", func(t *testing.T) {
		lister, err := h.Filelist(sftp.NewRequest("List", "/"))
		require.NoError(t, err)

		entries := make([]os.FileInfo, 8)
		n, listErr := lister.ListAt(entries, 0)
		require.ErrorIs(t, listErr, io.EOF)
		require.Equal(t, 3, n)
		assert.Equal(t, "hello.txt", entries[0].Name())
		assert.Equal(t, "players", entries[1].Name())
		assert.Equal(t, "private", entries[2].Name())
	})

	t.Run("list denied", func(t *testing.T) {
		_, err := h.Filelist(sftp.NewRequest("List", "/private"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	})

	t.Run("stat allowed", func(t *testing.T) {
		lister, err := h.Filelist(sftp.NewRequest("Stat", "/hello.txt"))
		require.NoError(t, err)

		entries := make([]os.FileInfo, 1)
		n, listErr := lister.ListAt(entries, 0)
		require.True(t, listErr == nil || listErr == io.EOF)
		require.Equal(t, 1, n)
		assert.Equal(t, int64(11), entries[0].Size())
	})

	t.Run("stat denied", func(t *testing.T) {
		_, err := h.Filelist(sftp.NewRequest("Stat", "/private/secret.txt"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	})

	t.Run("readlink unsupported", func(t *testing.T) {
		_, err := h.Filelist(sftp.NewRequest("Readlink", "/hello.txt"))
		assert.ErrorIs(t, err, sftp.ErrSSHFxOpUnsupported)
	})
}

func TestTranslateError(t *testing.T) {
	assert.Nil(t, translateError(nil))
	assert.Equal(t, sftp.ErrSSHFxNoSuchFile, translateError(os.ErrNotExist))
	assert.Equal(t, sftp.ErrSSHFxPermissionDenied, translateError(os.ErrPermission))
	assert.Equal(t, sftp.ErrSSHFxFailure, translateError(io.ErrUnexpectedEOF))

	// Wrapped os errors (what afero/os actually return) still map correctly.
	wrapped := &os.PathError{Op: "open", Path: "/mud/lib/secret", Err: os.ErrNotExist}
	assert.Equal(t, sftp.ErrSSHFxNoSuchFile, translateError(wrapped))
}

func TestErrorDoesNotLeakRealPath(t *testing.T) {
	h, root := newTestHandlers(t)

	_, err := h.Fileread(sftp.NewRequest("Get", "/players/alice/nonexistent.txt"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), root, "SFTP error must not expose the jail path")
	assert.Equal(t, sftp.ErrSSHFxNoSuchFile, err)
}

func TestToOsFileFlagsAppend(t *testing.T) {
	// Append without the Write bit must still open writable, not O_RDONLY.
	got := toOsFileFlags(sftp.FileOpenFlags{Append: true})
	assert.NotZero(t, got&os.O_WRONLY, "append open should be writable")
	assert.Zero(t, got&os.O_APPEND, "O_APPEND must not be set (conflicts with WriteAt)")

	got = toOsFileFlags(sftp.FileOpenFlags{Read: true, Append: true})
	assert.NotZero(t, got&os.O_RDWR, "read+append should be O_RDWR")

	// Plain read stays read-only.
	assert.Equal(t, os.O_RDONLY, toOsFileFlags(sftp.FileOpenFlags{Read: true}))
}

func TestListerAt(t *testing.T) {
	infos := make([]os.FileInfo, 3)
	l := listerAt(infos)

	buf := make([]os.FileInfo, 2)
	n, err := l.ListAt(buf, 0)
	assert.Equal(t, 2, n)
	assert.NoError(t, err)

	n, err = l.ListAt(buf, 2)
	assert.Equal(t, 1, n)
	assert.ErrorIs(t, err, io.EOF)

	n, err = l.ListAt(buf, 3)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, io.EOF)
}
