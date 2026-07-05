package ftpserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secsy/goftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/mmcdole/viking-ftpd/pkg/authentication"
	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

const testPassword = "password123"

func testHash() string {
	salt := []byte("somesalt12345678")
	hash := argon2.IDKey([]byte(testPassword), salt, 1, 64*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		64*1024, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

// startTestFTP starts a real FTP server on an ephemeral port with user "alice"
// (home /players/alice) and the testTree permission set, and returns its addr.
func startTestFTP(t *testing.T) (*Server, string) {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "private"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "players", "alice"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello world"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "private", "secret.txt"), []byte("secret"), 0644))

	charSource := users.NewMemorySource()
	charSource.AddUser(&users.User{Username: "alice", PasswordHash: testHash(), Level: users.WIZARD})

	authenticator := authentication.NewAuthenticator(charSource, authentication.NewVerifier())
	authorizer := authorization.NewAuthorizer(&stubAccessSource{testTree()}, charSource, time.Minute)

	// Bind the listener here so the test knows the ephemeral address without
	// racing ftpserverlib's internal listener field.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()

	server, err := New(&Config{
		RootDir:       root,
		HomePattern:   "players/%s",
		PasvPortRange: [2]int{0, 0}, // let the OS pick passive ports
		IdleTimeout:   30 * time.Second,
		Listener:      listener,
	}, authorizer, authenticator, "test")
	require.NoError(t, err)

	go server.ListenAndServe()
	t.Cleanup(func() { server.Stop() })

	return server, addr
}

func dial(t *testing.T, addr, user, password string) *goftp.Client {
	t.Helper()
	client, err := goftp.DialConfig(goftp.Config{
		User:               user,
		Password:           password,
		ConnectionsPerHost: 2,
		Timeout:            5 * time.Second,
	}, addr)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}

func TestFTPAuthentication(t *testing.T) {
	_, addr := startTestFTP(t)

	t.Run("valid login", func(t *testing.T) {
		client := dial(t, addr, "alice", testPassword)
		_, err := client.ReadDir("/")
		require.NoError(t, err)
	})

	t.Run("wrong password", func(t *testing.T) {
		client := dial(t, addr, "alice", "wrong")
		// goftp authenticates lazily on first use.
		_, err := client.ReadDir("/")
		assert.Error(t, err)
	})

	t.Run("unknown user", func(t *testing.T) {
		client := dial(t, addr, "mallory", "whatever")
		_, err := client.ReadDir("/")
		assert.Error(t, err)
	})
}

func TestFTPStartsInHomeDirectory(t *testing.T) {
	_, addr := startTestFTP(t)
	client := dial(t, addr, "alice", testPassword)

	wd, err := client.Getwd()
	require.NoError(t, err)
	assert.Equal(t, "/players/alice", wd)
}

func TestFTPFileOperations(t *testing.T) {
	_, addr := startTestFTP(t)
	client := dial(t, addr, "alice", testPassword)

	t.Run("download", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, client.Retrieve("/hello.txt", &buf))
		assert.Equal(t, "hello world", buf.String())
	})

	t.Run("upload into home then read back", func(t *testing.T) {
		require.NoError(t, client.Store("upload.txt", bytes.NewBufferString("uploaded")))

		var buf bytes.Buffer
		require.NoError(t, client.Retrieve("/players/alice/upload.txt", &buf))
		assert.Equal(t, "uploaded", buf.String())
	})

	t.Run("list", func(t *testing.T) {
		entries, err := client.ReadDir("/")
		require.NoError(t, err)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		assert.Contains(t, names, "hello.txt")
		assert.Contains(t, names, "players")
	})

	t.Run("mkdir rename delete", func(t *testing.T) {
		_, err := client.Mkdir("/players/alice/dir")
		require.NoError(t, err)
		require.NoError(t, client.Rename("/players/alice/dir", "/players/alice/dir2"))
		require.NoError(t, client.Rmdir("/players/alice/dir2"))
	})
}

func TestFTPPermissionDenied(t *testing.T) {
	_, addr := startTestFTP(t)
	client := dial(t, addr, "alice", testPassword)

	t.Run("read denied", func(t *testing.T) {
		var buf bytes.Buffer
		err := client.Retrieve("/private/secret.txt", &buf)
		assert.Error(t, err)
	})

	t.Run("list denied", func(t *testing.T) {
		_, err := client.ReadDir("/private")
		assert.Error(t, err)
	})

	t.Run("upload to root denied", func(t *testing.T) {
		err := client.Store("/denied.txt", bytes.NewBufferString("x"))
		assert.Error(t, err)
	})

	t.Run("rename to denied target", func(t *testing.T) {
		require.NoError(t, client.Store("/players/alice/movable.txt", bytes.NewBufferString("m")))
		err := client.Rename("/players/alice/movable.txt", "/escaped.txt")
		assert.Error(t, err)
	})
}

// TestFTPUploadPermissionsClamped confirms uploads land at 0644, not 0777.
func TestFTPUploadPermissionsClamped(t *testing.T) {
	server, addr := startTestFTP(t)
	client := dial(t, addr, "alice", testPassword)

	require.NoError(t, client.Store("clamped.txt", bytes.NewBufferString("data")))

	info, err := os.Stat(filepath.Join(server.config.RootDir, "players", "alice", "clamped.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestFTPConnectionMetrics(t *testing.T) {
	server, addr := startTestFTP(t)
	assert.False(t, server.GetStartTime().IsZero())

	client := dial(t, addr, "alice", testPassword)
	_, err := client.ReadDir("/") // force a control connection + login
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return server.GetTotalConnections() >= 1
	}, 2*time.Second, 10*time.Millisecond)
}
