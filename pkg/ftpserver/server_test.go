package ftpserver

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ftpserverlib "github.com/fclairamb/ftpserverlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
	"github.com/mmcdole/viking-ftpd/pkg/vfs"
)

// fakeContext is a minimal ftpserverlib.ClientContext for driver tests. Only
// the methods the driver actually calls are implemented; any other call would
// panic on the nil embedded interface, flagging accidental reliance on
// unimplemented behavior.
type fakeContext struct {
	ftpserverlib.ClientContext
	path      string
	debug     bool
	setPathTo string
}

func (f *fakeContext) Path() string     { return f.path }
func (f *fakeContext) SetPath(p string) { f.setPathTo = p }
func (f *fakeContext) SetDebug(d bool)  { f.debug = d }
func (f *fakeContext) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

type stubAccessSource struct {
	tree map[string]interface{}
}

func (s *stubAccessSource) LoadAccessData() (map[string]interface{}, error) {
	return s.tree, nil
}

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

// newTestClient builds an ftpClient for "alice" with working directory cwd,
// over a temp dir seeded with /hello.txt, /private/secret.txt, and
// /players/alice/note.txt.
func newTestClient(t *testing.T, cwd string) (*ftpClient, string) {
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

	return &ftpClient{
		fs: vfs.New(root, "alice", authorizer, "ftp"),
		cc: &fakeContext{path: cwd},
	}, root
}

func TestResolvePath(t *testing.T) {
	c := &ftpClient{cc: &fakeContext{path: "/players/alice"}}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"absolute", "/hello.txt", "/hello.txt"},
		{"absolute cleaned", "/a/../b", "/b"},
		{"relative to cwd", "note.txt", "/players/alice/note.txt"},
		{"relative dot", ".", "/players/alice"},
		{"relative parent", "..", "/players"},
		{"relative nested", "sub/x", "/players/alice/sub/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, c.resolvePath(tc.in))
		})
	}
}

func TestClientDelegatesAuthz(t *testing.T) {
	// Working directory is the home dir, so relative paths resolve there.
	c, root := newTestClient(t, "/players/alice")

	t.Run("read allowed absolute", func(t *testing.T) {
		f, err := c.Open("/hello.txt")
		require.NoError(t, err)
		f.Close()
	})

	t.Run("read denied", func(t *testing.T) {
		_, err := c.Open("/private/secret.txt")
		assert.ErrorIs(t, err, os.ErrPermission)
	})

	t.Run("write allowed in home (relative)", func(t *testing.T) {
		f, err := c.Create("upload.txt")
		require.NoError(t, err)
		require.NoError(t, f.Close())
		info, err := os.Stat(filepath.Join(root, "players", "alice", "upload.txt"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
	})

	t.Run("write denied outside home", func(t *testing.T) {
		_, err := c.Create("/denied.txt")
		assert.ErrorIs(t, err, os.ErrPermission)
	})

	t.Run("mkdir denied outside home", func(t *testing.T) {
		assert.ErrorIs(t, c.Mkdir("/nope", 0755), os.ErrPermission)
	})

	t.Run("rename requires both writable", func(t *testing.T) {
		assert.ErrorIs(t, c.Rename("note.txt", "/escaped.txt"), os.ErrPermission)
		require.NoError(t, c.Rename("note.txt", "renamed.txt"))
	})

	t.Run("readdir sorted", func(t *testing.T) {
		entries, err := c.ReadDir("/")
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(entries), 3)
		assert.Equal(t, "hello.txt", entries[0].Name())
	})
}

// ensure fakeContext satisfies the interface at compile time
var _ ftpserverlib.ClientContext = (*fakeContext)(nil)
