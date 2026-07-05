package sftpserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
)

// loadOrGenerateHostKey returns the server's SSH host key, generating an
// ed25519 key at path on first use. An existing but unparseable or
// group/world-accessible key file is a hard error rather than a trigger to
// regenerate, so clients never see an unexpected host key change.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("checking host key %s: %w", path, err)
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("host key %s has insecure permissions %04o (must not be group/world accessible)", path, info.Mode().Perm())
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parsing host key %s: %w", path, err)
		}
		return signer, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating host key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "vkftpd host key")
	if err != nil {
		return nil, fmt.Errorf("encoding host key: %w", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("writing host key %s: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	logging.App.Info("Generated SSH host key", "path", path, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}
