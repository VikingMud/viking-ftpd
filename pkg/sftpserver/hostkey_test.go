package sftpserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestLoadOrGenerateHostKey(t *testing.T) {
	t.Run("generates key when missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host_key")

		signer, err := loadOrGenerateHostKey(path)
		require.NoError(t, err)
		require.NotNil(t, signer)
		assert.Equal(t, "ssh-ed25519", signer.PublicKey().Type())

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("loads existing key with stable identity", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host_key")

		first, err := loadOrGenerateHostKey(path)
		require.NoError(t, err)

		second, err := loadOrGenerateHostKey(path)
		require.NoError(t, err)

		assert.Equal(t, ssh.FingerprintSHA256(first.PublicKey()), ssh.FingerprintSHA256(second.PublicKey()))
	})

	t.Run("fails on corrupt key instead of regenerating", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host_key")
		require.NoError(t, os.WriteFile(path, []byte("not a key"), 0600))

		_, err := loadOrGenerateHostKey(path)
		require.Error(t, err)

		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, "not a key", string(data), "corrupt key file must not be overwritten")
	})

	t.Run("fails on insecure permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host_key")
		_, err := loadOrGenerateHostKey(path)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(path, 0644))

		_, err = loadOrGenerateHostKey(path)
		assert.ErrorContains(t, err, "insecure permissions")
	})
}
