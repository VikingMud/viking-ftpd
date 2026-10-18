# v2.3.0

SFTP now supports hybrid post-quantum key exchange (`mlkem768x25519-sha256`)
through an upgrade to `golang.org/x/crypto` v0.58.0. Compatible clients negotiate
this automatically, preventing OpenSSH's warning about "store now, decrypt
later" attacks when this exchange is used.

Traditional key exchanges remain available for older clients. Integration tests
cover default negotiation, forced post-quantum exchange, and traditional
Curve25519 and ECDH P-256 exchanges, with upload/download checks. This does not
guarantee compatibility with clients requiring obsolete algorithms.

Existing configuration, passwords, authorized keys, and the SSH host key can be
kept. No host-key rotation is needed. Source builds now require Go 1.26 or later;
the release binaries do not require Go to be installed.

## Updating Viking

1. Download `vkftpd-linux-amd64` for an x86-64 Linux server.
2. Verify its checksum against `SHA256SUMS` and run it with `--version`.
3. Stop the existing daemon, retain its binary for rollback, and install the new
   executable in its place. Keep the existing config and SSH host-key file.
4. Start the daemon using the existing service configuration. The restart
   disconnects active transfers, so choose a quiet time.
5. Connect with `sftp -vv -P PORT USER@HOST` and check for
   `kex: algorithm: mlkem768x25519-sha256`. Verify a login and file transfer.

If rollback is needed, stop the service, restore the previous binary, and start
it again with the same configuration.
