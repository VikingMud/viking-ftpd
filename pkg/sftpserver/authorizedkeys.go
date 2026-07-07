package sftpserver

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

// authorizedKeysFile is the per-player public key file, relative to the
// player's home directory (e.g. /players/<player>/.authorized_keys). Players
// upload it themselves over FTP/SFTP; its format is one OpenSSH public key
// per line, the same as ~/.ssh/authorized_keys.
const authorizedKeysFile = ".authorized_keys"

// maxAuthorizedKeysSize caps how much of a player-controlled key file is
// read. 64 KiB fits hundreds of keys; anything larger is refused outright
// rather than truncated, so a partially-read file can never drop keys
// silently.
const maxAuthorizedKeysSize = 64 * 1024

// UserSource looks up MUD characters. Satisfied by any users.Source; used to
// require that a character exists before its authorized_keys file is
// consulted, so keys in a stale directory of a deleted player grant nothing.
type UserSource interface {
	LoadUser(username string) (*users.User, error)
}

// publicKeyCallback authenticates SSH public-key attempts against the keys
// the player has uploaded to authorizedKeysFile in their home directory.
// x/crypto/ssh invokes it for both the advisory "do you accept this key"
// query and the signed attempt, and verifies the signature itself; this
// callback only decides whether the offered key is authorized.
//
// Unlike the password path there is no constant-time dance here: an attacker
// cannot learn anything useful from public-key auth timing that the password
// method (which stays enumeration-safe) does not already hide, and OpenSSH
// makes the same trade.
func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()
	fingerprint := ssh.FingerprintSHA256(key)

	if _, err := s.userSource.LoadUser(username); err != nil {
		logging.Access.LogAuth("login", username, "failed", "method", "publickey", "fingerprint", fingerprint, "error", err, "client_ip", conn.RemoteAddr().String(), "protocol", "sftp")
		return nil, fmt.Errorf("unknown public key")
	}

	authorized, err := s.loadAuthorizedKeys(username)
	if err != nil {
		logging.App.Warn("Failed to read authorized_keys", "user", username, "error", err)
	}

	for _, candidate := range authorized {
		if candidate.Type() == key.Type() && bytes.Equal(candidate.Marshal(), key.Marshal()) {
			// Success is logged after the handshake completes (see
			// handleConn), once the signature has actually been verified;
			// the fingerprint travels there via Permissions.
			return &ssh.Permissions{Extensions: map[string]string{permPubKeyFingerprint: fingerprint}}, nil
		}
	}

	logging.Access.LogAuth("login", username, "failed", "method", "publickey", "fingerprint", fingerprint, "client_ip", conn.RemoteAddr().String(), "protocol", "sftp")
	return nil, fmt.Errorf("unknown public key")
}

// permPubKeyFingerprint is the ssh.Permissions extension key carrying the
// authenticated key's fingerprint from the auth callback to the session.
const permPubKeyFingerprint = "vkftpd-pubkey-fingerprint"

// loadAuthorizedKeys reads and parses the player's authorized_keys file.
// A missing file or home directory is the common case (player never uploaded
// keys) and returns no keys and no error. Unparseable lines are skipped so
// one bad paste doesn't lock a player out of their remaining keys.
func (s *Server) loadAuthorizedKeys(username string) ([]ssh.PublicKey, error) {
	path, err := s.authorizedKeysPath(username)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxAuthorizedKeysSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAuthorizedKeysSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxAuthorizedKeysSize)
	}

	return parseAuthorizedKeys(data), nil
}

// authorizedKeysPath resolves the on-disk path of username's key file inside
// the jail. The username comes straight off the wire, so it must pass the
// same traversal guard the character store uses before being joined into a
// path.
func (s *Server) authorizedKeysPath(username string) (string, error) {
	if s.config.HomePattern == "" {
		return "", fmt.Errorf("no home pattern configured")
	}
	if !users.IsValidUsername(username) {
		return "", fmt.Errorf("invalid username")
	}
	home := filepath.Clean(fmt.Sprintf(s.config.HomePattern, username))
	return filepath.Join(s.config.RootDir, home, authorizedKeysFile), nil
}

// parseAuthorizedKeys extracts the public keys from authorized_keys-format
// data, skipping blank lines, comments, and lines that fail to parse.
func parseAuthorizedKeys(data []byte) []ssh.PublicKey {
	var keys []ssh.PublicKey
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}
