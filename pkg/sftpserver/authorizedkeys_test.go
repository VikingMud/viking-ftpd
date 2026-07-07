package sftpserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// genKey returns a fresh ed25519 keypair as an SSH signer plus its
// authorized_keys line.
func genKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return signer, string(ssh.MarshalAuthorizedKey(sshPub))
}

// writeAuthorizedKeys writes content to alice-style key file for user under root.
func writeAuthorizedKeys(t *testing.T, root, user, content string) {
	t.Helper()
	dir := filepath.Join(root, "players", user)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, authorizedKeysFile), []byte(content), 0644))
}

func dialSSHKey(t *testing.T, addr, user string, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

func TestParseAuthorizedKeys(t *testing.T) {
	_, line1 := genKey(t)
	_, line2 := genKey(t)

	t.Run("valid keys with noise", func(t *testing.T) {
		data := "# my laptop\n\n" + line1 + "not a key at all\n" + line2 + "   \n"
		keys := parseAuthorizedKeys([]byte(data))
		assert.Len(t, keys, 2)
	})

	t.Run("options prefix is accepted", func(t *testing.T) {
		keys := parseAuthorizedKeys([]byte("no-pty,command=\"true\" " + line1))
		assert.Len(t, keys, 1)
	})

	t.Run("empty and garbage only", func(t *testing.T) {
		assert.Empty(t, parseAuthorizedKeys(nil))
		assert.Empty(t, parseAuthorizedKeys([]byte("# comment\ngarbage\n")))
	})
}

func TestAuthorizedKeysPath(t *testing.T) {
	s := &Server{config: &Config{RootDir: "/mud", HomePattern: "players/%s"}}

	t.Run("valid username", func(t *testing.T) {
		path, err := s.authorizedKeysPath("alice")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("/mud", "players", "alice", authorizedKeysFile), path)
	})

	t.Run("traversal usernames rejected", func(t *testing.T) {
		for _, name := range []string{"../wiz", "a/b", "..", "", "a b", `a\b`} {
			_, err := s.authorizedKeysPath(name)
			assert.Error(t, err, "username %q should be rejected", name)
		}
	})

	t.Run("no home pattern", func(t *testing.T) {
		bare := &Server{config: &Config{RootDir: "/mud"}}
		_, err := bare.authorizedKeysPath("alice")
		assert.Error(t, err)
	})
}

func TestPublicKeyAuthentication(t *testing.T) {
	server, addr := startTestServer(t)
	root := server.config.RootDir

	authorized, authorizedLine := genKey(t)
	intruder, _ := genKey(t)

	t.Run("no key file uploaded", func(t *testing.T) {
		_, err := dialSSHKey(t, addr, "alice", authorized)
		require.Error(t, err)
	})

	writeAuthorizedKeys(t, root, "alice", "# laptop\n"+authorizedLine)

	t.Run("authorized key succeeds", func(t *testing.T) {
		client, err := dialSSHKey(t, addr, "alice", authorized)
		require.NoError(t, err)
		client.Close()
	})

	t.Run("unauthorized key fails", func(t *testing.T) {
		_, err := dialSSHKey(t, addr, "alice", intruder)
		require.Error(t, err)
	})

	t.Run("password auth still works alongside", func(t *testing.T) {
		client, err := dialSSH(t, addr, "alice", testPassword)
		require.NoError(t, err)
		client.Close()
	})

	t.Run("key for nonexistent character grants nothing", func(t *testing.T) {
		// A leftover player directory with keys, but no character file:
		// the character-existence check must refuse it.
		writeAuthorizedKeys(t, root, "ghost", authorizedLine)
		_, err := dialSSHKey(t, addr, "ghost", authorized)
		require.Error(t, err)
	})

	t.Run("garbage lines do not disable remaining keys", func(t *testing.T) {
		writeAuthorizedKeys(t, root, "alice", "garbage line\n"+authorizedLine)
		client, err := dialSSHKey(t, addr, "alice", authorized)
		require.NoError(t, err)
		client.Close()
	})

	t.Run("oversized key file is refused", func(t *testing.T) {
		filler := "# " + strings.Repeat("x", 1022) + "\n"
		writeAuthorizedKeys(t, root, "alice", strings.Repeat(filler, 65)+authorizedLine)
		_, err := dialSSHKey(t, addr, "alice", authorized)
		require.Error(t, err)
	})
}

// TestPublicKeySessionWorks verifies a key-authenticated session gets the
// same jailed SFTP environment as a password one.
func TestPublicKeySessionWorks(t *testing.T) {
	server, addr := startTestServer(t)

	signer, line := genKey(t)
	writeAuthorizedKeys(t, server.config.RootDir, "alice", line)

	sshClient, err := dialSSHKey(t, addr, "alice", signer)
	require.NoError(t, err)
	defer sshClient.Close()

	sftpClient, err := sftp.NewClient(sshClient)
	require.NoError(t, err)
	defer sftpClient.Close()

	wd, err := sftpClient.Getwd()
	require.NoError(t, err)
	assert.Equal(t, "/players/alice", wd)

	_, err = sftpClient.Open("/private/secret.txt")
	require.Error(t, err, "authorization must still apply to key-authenticated sessions")
}
