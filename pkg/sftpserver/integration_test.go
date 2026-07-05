package sftpserver

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	"github.com/mmcdole/viking-ftpd/pkg/authentication"
	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

const testPassword = "password123"

// testHash returns an argon2id PHC hash of testPassword
func testHash() string {
	salt := []byte("somesalt12345678")
	hash := argon2.IDKey([]byte(testPassword), salt, 1, 64*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		64*1024, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

// startTestServer starts a full SFTP server on an ephemeral port with user
// "alice" (home /players/alice) and the permission tree from testTree.
func startTestServer(t *testing.T) (*Server, string) {
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

	server, err := New(&Config{
		ListenAddr:  "127.0.0.1",
		Port:        0,
		RootDir:     root,
		HomePattern: "players/%s",
		HostKeyFile: filepath.Join(t.TempDir(), "host_key"),
		IdleTimeout: 30 * time.Second,
	}, authorizer, authenticator, "test")
	require.NoError(t, err)

	go server.ListenAndServe()
	t.Cleanup(func() { server.Stop() })

	var addr net.Addr
	require.Eventually(t, func() bool {
		addr = server.Addr()
		return addr != nil
	}, 5*time.Second, 10*time.Millisecond, "server did not start listening")

	return server, addr.String()
}

func dialSSH(t *testing.T, addr, user, password string) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

func dialSFTP(t *testing.T, addr string) (*ssh.Client, *sftp.Client) {
	t.Helper()
	sshClient, err := dialSSH(t, addr, "alice", testPassword)
	require.NoError(t, err)
	t.Cleanup(func() { sshClient.Close() })

	sftpClient, err := sftp.NewClient(sshClient)
	require.NoError(t, err)
	t.Cleanup(func() { sftpClient.Close() })

	return sshClient, sftpClient
}

func TestAuthentication(t *testing.T) {
	_, addr := startTestServer(t)

	t.Run("valid password", func(t *testing.T) {
		client, err := dialSSH(t, addr, "alice", testPassword)
		require.NoError(t, err)
		client.Close()
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := dialSSH(t, addr, "alice", "wrong")
		require.Error(t, err)
	})

	t.Run("nonexistent user fails the same way", func(t *testing.T) {
		_, err := dialSSH(t, addr, "mallory", "whatever")
		require.Error(t, err)
	})
}

func TestSessionStartsInHomeDirectory(t *testing.T) {
	_, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	wd, err := client.Getwd()
	require.NoError(t, err)
	assert.Equal(t, "/players/alice", wd)
}

func TestFileOperations(t *testing.T) {
	_, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	t.Run("download", func(t *testing.T) {
		f, err := client.Open("/hello.txt")
		require.NoError(t, err)
		defer f.Close()

		data, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(data))
	})

	t.Run("upload and read back", func(t *testing.T) {
		f, err := client.Create("/players/alice/upload.txt")
		require.NoError(t, err)
		_, err = f.Write([]byte("uploaded content"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		rf, err := client.Open("/players/alice/upload.txt")
		require.NoError(t, err)
		defer rf.Close()
		data, err := io.ReadAll(rf)
		require.NoError(t, err)
		assert.Equal(t, "uploaded content", string(data))
	})

	t.Run("list directory", func(t *testing.T) {
		entries, err := client.ReadDir("/")
		require.NoError(t, err)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		assert.Contains(t, names, "hello.txt")
		assert.Contains(t, names, "players")
	})

	t.Run("mkdir rename remove", func(t *testing.T) {
		require.NoError(t, client.Mkdir("/players/alice/dir"))
		require.NoError(t, client.Rename("/players/alice/dir", "/players/alice/dir2"))
		require.NoError(t, client.RemoveDirectory("/players/alice/dir2"))
	})

	t.Run("stat", func(t *testing.T) {
		fi, err := client.Stat("/hello.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(11), fi.Size())
	})
}

func TestPermissionDenied(t *testing.T) {
	_, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	t.Run("read denied", func(t *testing.T) {
		_, err := client.Open("/private/secret.txt")
		require.Error(t, err)
		assert.True(t, os.IsPermission(err), "expected permission error, got: %v", err)
	})

	t.Run("list denied", func(t *testing.T) {
		_, err := client.ReadDir("/private")
		require.Error(t, err)
	})

	t.Run("write denied", func(t *testing.T) {
		_, err := client.Create("/denied.txt")
		require.Error(t, err)
		assert.True(t, os.IsPermission(err), "expected permission error, got: %v", err)
	})

	t.Run("rename to denied target", func(t *testing.T) {
		f, err := client.Create("/players/alice/movable.txt")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		err = client.Rename("/players/alice/movable.txt", "/escaped.txt")
		require.Error(t, err)
	})

	t.Run("symlink denied", func(t *testing.T) {
		err := client.Symlink("/players/alice/upload.txt", "/players/alice/link")
		require.Error(t, err)
	})
}

func TestShellAndExecRefused(t *testing.T) {
	_, addr := startTestServer(t)
	sshClient, err := dialSSH(t, addr, "alice", testPassword)
	require.NoError(t, err)
	defer sshClient.Close()

	t.Run("shell refused", func(t *testing.T) {
		session, err := sshClient.NewSession()
		require.NoError(t, err)
		defer session.Close()
		assert.Error(t, session.Shell())
	})

	t.Run("exec refused", func(t *testing.T) {
		session, err := sshClient.NewSession()
		require.NoError(t, err)
		defer session.Close()
		assert.Error(t, session.Run("ls"))
	})

	t.Run("other subsystem refused", func(t *testing.T) {
		session, err := sshClient.NewSession()
		require.NoError(t, err)
		defer session.Close()
		assert.Error(t, session.RequestSubsystem("netconf"))
	})
}

func TestConnectionMetrics(t *testing.T) {
	server, addr := startTestServer(t)

	require.Equal(t, int32(0), server.GetActiveConnections())

	sshClient, err := dialSSH(t, addr, "alice", testPassword)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return server.GetActiveConnections() == 1
	}, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), server.GetTotalConnections())
	assert.False(t, server.GetStartTime().IsZero())

	sshClient.Close()

	assert.Eventually(t, func() bool {
		return server.GetActiveConnections() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestStopClosesActiveConnections(t *testing.T) {
	server, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	done := make(chan error, 1)
	go func() { done <- server.Stop() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return with an active connection")
	}

	_, err := client.Getwd()
	assert.Error(t, err, "client should be disconnected after Stop")
}

// TestStopWithHalfOpenConnection verifies Stop does not block on a client that
// connected but never completed the SSH handshake (which would otherwise hold
// handleConn until the 30s handshake deadline).
func TestStopWithHalfOpenConnection(t *testing.T) {
	server, addr := startTestServer(t)

	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer raw.Close()

	// Wait until the server has registered the connection.
	require.Eventually(t, func() bool {
		return server.GetActiveConnections() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- server.Stop() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked on a half-open connection (should close it, not wait for handshake timeout)")
	}
}

// TestErrorMessagesDoNotLeakRealPath ensures the jail's real filesystem path
// never appears in errors sent to SFTP clients.
func TestErrorMessagesDoNotLeakRealPath(t *testing.T) {
	server, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)
	root := server.config.RootDir

	_, err := client.Stat("/players/alice/does-not-exist")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), root)

	_, err = client.Open("/players/alice/also-missing")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), root)
	assert.True(t, os.IsNotExist(err), "should map to no-such-file, got: %v", err)
}

// TestChownIsIgnored verifies a client chown request succeeds without changing
// ownership (it is deliberately a no-op in this authz model).
func TestChownIsIgnored(t *testing.T) {
	_, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	f, err := client.Create("/players/alice/owned.txt")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Chown to root:root would fail with EPERM if actually attempted as non-root;
	// because the server ignores uid/gid, the request succeeds.
	err = client.Chown("/players/alice/owned.txt", 0, 0)
	assert.NoError(t, err)
}

// TestAppendUpload verifies an append-mode open works end to end.
func TestAppendUpload(t *testing.T) {
	_, addr := startTestServer(t)
	_, client := dialSFTP(t, addr)

	f, err := client.Create("/players/alice/log.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("first\n"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Open for append (the write-intent regression: Append must open writable,
	// not O_RDONLY) and resume at end-of-file as a real client does.
	af, err := client.OpenFile("/players/alice/log.txt", os.O_WRONLY|os.O_APPEND)
	require.NoError(t, err)
	_, err = af.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	_, err = af.Write([]byte("second\n"))
	require.NoError(t, err)
	require.NoError(t, af.Close())

	rf, err := client.Open("/players/alice/log.txt")
	require.NoError(t, err)
	defer rf.Close()
	data, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, "first\nsecond\n", string(data))
}
