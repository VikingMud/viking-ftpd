package sftpserver

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
	"github.com/mmcdole/viking-ftpd/pkg/vfs"
)

type stubAccessSource struct {
	tree map[string]interface{}
}

func (s *stubAccessSource) LoadAccessData() (map[string]interface{}, error) {
	return s.tree, nil
}

// testTree gives everyone Read everywhere except /private, which is revoked.
// Write access comes only from the implicit GrantGrant on players/<self>.
// (Shared with integration_test.go.)
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

// newTestHandlers builds handlers backed by a real vfs.FS for user "alice" over
// a temp dir with /hello.txt, /private/secret.txt, and /players/alice/note.txt.
// Per-operation authorization is covered exhaustively in pkg/vfs; these tests
// focus on the SFTP protocol-translation layer.
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

	return &sftpHandlers{fs: vfs.New(root, "alice", authorizer, "sftp")}, root
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

// TestHandlerTranslatesDenial confirms an authorization denial from vfs becomes
// the generic SFTP permission-denied status, not a raw error.
func TestHandlerTranslatesDenial(t *testing.T) {
	h, _ := newTestHandlers(t)

	_, err := h.Fileread(sftp.NewRequest("Get", "/private/secret.txt"))
	assert.Equal(t, sftp.ErrSSHFxPermissionDenied, err)
}

// TestHandlerErrorDoesNotLeakRealPath ensures the jail path never reaches the
// client through a translated error.
func TestHandlerErrorDoesNotLeakRealPath(t *testing.T) {
	h, root := newTestHandlers(t)

	_, err := h.Fileread(sftp.NewRequest("Get", "/players/alice/nonexistent.txt"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), root)
	assert.Equal(t, sftp.ErrSSHFxNoSuchFile, err)
}

func TestFilecmdLinksUnsupported(t *testing.T) {
	h, _ := newTestHandlers(t)

	for _, method := range []string{"Symlink", "Link"} {
		req := sftp.NewRequest(method, "/players/alice/target")
		req.Target = "/players/alice/link"
		assert.ErrorIs(t, h.Filecmd(req), sftp.ErrSSHFxOpUnsupported, method)
	}
}

func TestFilelistReadlinkUnsupported(t *testing.T) {
	h, _ := newTestHandlers(t)
	_, err := h.Filelist(sftp.NewRequest("Readlink", "/hello.txt"))
	assert.ErrorIs(t, err, sftp.ErrSSHFxOpUnsupported)
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
