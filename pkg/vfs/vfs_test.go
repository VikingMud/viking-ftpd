package vfs

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

type stubAccessSource struct {
	tree map[string]interface{}
}

func (s *stubAccessSource) LoadAccessData() (map[string]interface{}, error) {
	return s.tree, nil
}

// testTree gives everyone Read everywhere except /private (revoked). Write
// comes only from the implicit GrantGrant on players/<self>.
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

// newTestFS builds an FS for user "alice" over a temp dir seeded with
// /hello.txt, /private/secret.txt, and /players/alice/note.txt.
func newTestFS(t *testing.T) (*FS, string) {
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

	return New(root, "alice", authorizer, "test"), root
}

func TestOpenReadAuthz(t *testing.T) {
	fs, _ := newTestFS(t)

	f, err := fs.Open("/hello.txt")
	require.NoError(t, err)
	f.Close()

	_, err = fs.Open("/private/secret.txt")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestOpenFileWriteAuthz(t *testing.T) {
	fs, root := newTestFS(t)

	f, err := fs.OpenFile("/players/alice/new.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	require.NoError(t, err)
	_, err = f.Write([]byte("hi"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Upload permissions are clamped to 0644.
	info, err := os.Stat(filepath.Join(root, "players", "alice", "new.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

	_, err = fs.OpenFile("/denied.txt", os.O_WRONLY|os.O_CREATE, os.ModePerm)
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.NoFileExists(t, filepath.Join(root, "denied.txt"))
}

func TestCreateClampsPerm(t *testing.T) {
	fs, root := newTestFS(t)

	f, err := fs.Create("/players/alice/c.txt")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	info, err := os.Stat(filepath.Join(root, "players", "alice", "c.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

	_, err = fs.Create("/nope.txt")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestReadDirSorted(t *testing.T) {
	fs, _ := newTestFS(t)

	entries, err := fs.ReadDirSorted("/")
	require.NoError(t, err)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	assert.Equal(t, []string{"hello.txt", "players", "private"}, names)

	_, err = fs.ReadDirSorted("/private")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestMkdirRemoveAuthz(t *testing.T) {
	fs, root := newTestFS(t)

	require.NoError(t, fs.Mkdir("/players/alice/d", 0755))
	assert.DirExists(t, filepath.Join(root, "players", "alice", "d"))
	assert.ErrorIs(t, fs.Mkdir("/nope", 0755), os.ErrPermission)

	require.NoError(t, fs.Remove("/players/alice/note.txt"))
	assert.NoFileExists(t, filepath.Join(root, "players", "alice", "note.txt"))
	assert.ErrorIs(t, fs.Remove("/hello.txt"), os.ErrPermission)
}

func TestRenameRequiresWriteBothSides(t *testing.T) {
	fs, _ := newTestFS(t)

	require.NoError(t, fs.Rename("/players/alice/note.txt", "/players/alice/renamed.txt"))
	// Target not writable.
	assert.ErrorIs(t, fs.Rename("/players/alice/renamed.txt", "/escaped.txt"), os.ErrPermission)
	// Source not writable.
	assert.ErrorIs(t, fs.Rename("/hello.txt", "/players/alice/stolen.txt"), os.ErrPermission)
}

func TestStatAuthz(t *testing.T) {
	fs, _ := newTestFS(t)

	fi, err := fs.Stat("/hello.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(11), fi.Size())

	_, err = fs.Stat("/private/secret.txt")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestChmodChownChtimesAuthz(t *testing.T) {
	fs, _ := newTestFS(t)

	require.NoError(t, fs.Chmod("/players/alice/note.txt", 0600))
	assert.ErrorIs(t, fs.Chmod("/hello.txt", 0600), os.ErrPermission)

	assert.ErrorIs(t, fs.Chown("/hello.txt", 0, 0), os.ErrPermission)

	require.NoError(t, fs.Chtimes("/players/alice/note.txt", time.Now(), time.Now()))
	assert.ErrorIs(t, fs.Chtimes("/hello.txt", time.Now(), time.Now()), os.ErrPermission)
}

func TestOpenFileReadWriteRoundTrip(t *testing.T) {
	fs, _ := newTestFS(t)

	f, err := fs.OpenFile("/players/alice/note.txt", os.O_RDWR, 0)
	require.NoError(t, err)
	defer f.Close()

	_, err = f.WriteAt([]byte("NOTE"), 0)
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = f.ReadAt(buf, 0)
	require.True(t, err == nil || err == io.EOF)
	assert.Equal(t, "NOTE", string(buf))
}
