# VikingMUD FTP Daemon

A custom FTP and SFTP server designed specifically for [VikingMUD](https://www.vikingmud.org), providing secure file access with native integration into the MUD's [player authentication](docs/player_authentication.md) and hiearchical [authorization system](docs/viking_access_tree.md). This daemon understands [LPC serialized object format](https://github.com/mmcdole/viking-ftpd/blob/main/docs/lpc_object_format.md) and directly interfaces with the MUD's character database and access control trees.

Both protocols share the same authentication (MUD character passwords), the same per-path authorization (the MUD's access tree), the same filesystem jail, and the same access logs — SFTP is simply a more secure transport for the same access.


## Installation

### Building
Requires Go 1.22 or higher. Build using the provided Makefile:

```bash
make build   # Creates vkftpd binary with version information
./vkftpd --version  # Verify build
```

Or build manually with `go build`.

### Running
To start the server with your configuration:

```bash
./vkftpd --config config.json
```

## Configuration

Create a configuration file in JSON format. Example:

```json
{
    "listen_addr": "0.0.0.0",
    "port": 2121,
    "ftp_root_dir": "/mud/lib",
    "character_dir_path": "/mud/lib/characters",
    "access_file_path": "/mud/lib/dgd/sys/data/access.o",
    "home_pattern": "players/%s",
    "tls_cert_file": "/path/to/cert.pem",
    "tls_key_file": "/path/to/key.pem",
    "sftp_port": 2022,
    "ssh_host_key_file": "/path/to/vkftpd_host_key",
    "pasv_port_range": [2122, 2150],
    "pasv_address": "your.public.ip.address",
    "pasv_ip_verify": true,
    "max_connections": 10,
    "idle_timeout": 300,
    "character_cache_time": 60,
    "access_cache_time": 60,
    "access_log_path": "/mud/lib/log/vkftpd-access.log",
    "app_log_path": "/mud/lib/log/vkftpd-app.log",
    "log_level": "info",
    "max_log_size": 1000000,
    "log_verify_interval": 45,
    "status_dir": "/mud/lib/sys/ftp"
}
```

### Network Settings
- `listen_addr`: Address to listen on (e.g., "0.0.0.0" for all interfaces)
- `port`: Port to listen on (default: 2121)
- `pasv_port_range`: Range of ports for passive mode (default: [50000, 50100])
- `pasv_address`: Public IP address to advertise for passive mode connections (optional)
- `pasv_ip_verify`: Whether to verify data connection IP matches control IP (optional, default: false)
- `max_connections`: Maximum concurrent connections (default: 10)
- `idle_timeout`: Connection idle timeout in seconds (default: 300)

### File System Configuration
- `ftp_root_dir`: Root directory for FTP access (required)
- `character_dir_path`: Path to character files directory (required)
- `access_file_path`: Path to the MUD's access.o file (required)
- `home_pattern`: Pattern for user home directories (e.g., "players/%s")

### Security
- `tls_cert_file`: Path to TLS certificate file for optional FTPS support (optional)
- `tls_key_file`: Path to TLS private key file for optional FTPS support (optional)

If TLS certificate and key files are provided, the server will support both FTP and FTPS connections. If not provided, the server will operate in FTP-only mode.

### SFTP

SFTP (file transfer over SSH) is enabled by setting `sftp_port`:

- `sftp_port`: Port for the SFTP listener (optional; 0 or omitted = SFTP disabled, suggested: 2022)
- `sftp_listen_addr`: Address for the SFTP listener (optional, defaults to `listen_addr`)
- `ssh_host_key_file`: Path to the SSH host key (optional, defaults to `vkftpd_host_key` next to the config file)

Notes:

- SFTP shares `ftp_root_dir`, `home_pattern`, `max_connections`, and `idle_timeout` with the FTP server, and enforces the same per-path permissions from the MUD's access tree.
- If the host key file does not exist, an ed25519 key is generated on first start (mode 0600) and its fingerprint logged. An existing but corrupt or group/world-accessible key file is a startup error — the key is never silently regenerated, so clients never see an unexpected host key change.
- Authentication is by MUD password only; SSH public-key auth is not offered.
- Only the `sftp` subsystem is served. Shell, exec, and port-forwarding requests are refused, so `ssh` gives no shell and `scp` (which uses exec) does not work — use `sftp`/SFTP-capable clients.
- SFTP operations appear in the access log with the same `op=`/`status=` vocabulary as FTP; connect, disconnect, and login lines carry an extra `protocol=sftp` field. SFTP has no `chdir` operation (directory changes are client-side in the protocol).
- Symlink and hardlink creation, and readlink, are refused.

### Caching and Logging
- `character_cache_time`: How long to cache character data in seconds (default: 60)
- `access_cache_time`: How long to cache access.o data in seconds (default: 60)
- `access_log_path`: Path to access log file (optional)
- `app_log_path`: Path to application log file (optional)
- `log_level`: Log level (debug, info, warn, error, panic) (default: info)
- `max_log_size`: Maximum log file size in bytes before rotation (default: 1000000 / 1MB)
- `log_verify_interval`: Seconds between file verification checks to detect external moves (default: 45)

When logs exceed `max_log_size`, they are automatically rotated to timestamped archives in an `old/` subdirectory with format `<basename>.YYYYMMDD-HHMMSS`. The daemon also periodically verifies log files exist and recreates them if externally moved or deleted.

### Status Monitoring
- `status_dir`: Directory for status files (optional). When configured, writes three monitoring files: `last_start` (startup info), `running` (live metrics updated every 10s), and `last_stop` (shutdown reason). The MUD can detect crashes by checking if `running` is stale (>60s old) without a corresponding `last_stop` update.

## Package Overview

| Package | Description |
|---------|------------|
| `authentication` | Handles user authentication by verifying credentials against the MUD's [player authentication system](docs/player_authentication.md). Supports legacy unixcrypt and new Argon2id (PHC format) hashes. |
| `authorization` | Implements permission checking by parsing the MUD's `access.o` object tree. Validates user access rights against the MUD's [hierarchical permission system](docs/viking_access_tree.md). The access tree is cached to reduce filesystem reads. |
| `ftpserver` | Core FTP server implementation built on [ftpserverlib](https://github.com/fclairamb/ftpserverlib). Handles FTP protocol operations while integrating with MUD-specific authentication and authorization. |
| `sftpserver` | SFTP server built on [pkg/sftp](https://github.com/pkg/sftp) and `golang.org/x/crypto/ssh`. Serves only the SFTP subsystem (no shell/exec) with the same authentication, authorization, jail, and access logging as the FTP server. |
| `lpc` | Parses [LPC (Lars Pensjo C) serialized object format](https://github.com/mmcdole/viking-ftpd/blob/main/docs/lpc_object_format.md) used by LPMuds. Enables direct reading of MUD's data structures like the access control tree. |
| `users` | Manages user data by reading and caching the MUD's character files.  |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
