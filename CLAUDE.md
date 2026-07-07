# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Running
```bash
make build                           # Build with version info from git (uses ldflags)
go build ./cmd/vkftpd               # Build manually (version will be "dev")
./vkftpd --version                  # Check version
./vkftpd --config config.json       # Run with config
```

### Testing
```bash
go test ./...                        # Run all tests
go test -v ./pkg/authentication/...  # Run specific package tests with verbose output
go test -race ./...                  # Run with race detection
go test -run TestName ./pkg/path/... # Run single test by name
```

### Dependencies
```bash
go mod tidy                          # Clean up dependencies
go get -u ./...                      # Update all dependencies
```

## Architecture Overview

This is a specialized FTP server for VikingMUD that integrates with the MUD's authentication and authorization systems. The server parses LPC serialized objects and interfaces directly with the MUD's character database.

### Core Components

- **Main Entry Point** (`cmd/vkftpd/main.go`): CLI application using Cobra framework. Orchestrates initialization of all components in dependency order: logging → user source → authenticator → authorizer → FTP server. Configuration is loaded from JSON file specified via `--config` flag.

- **FTP Server** (`pkg/ftpserver/`): Core FTP protocol handling using [ftpserverlib](https://github.com/fclairamb/ftpserverlib). Implements the driver interface that integrates authentication and authorization checks into FTP operations. Supports both plain FTP and FTPS with optional TLS.

- **SFTP Server** (`pkg/sftpserver/`): Optional SFTP endpoint (enabled via `sftp_port`) built on `github.com/pkg/sftp`'s request-server and `golang.org/x/crypto/ssh`. Reuses the same authenticator, authorizer, filesystem jail, home-directory logic, and access logging as the FTP server. Serves only the `sftp` subsystem — shell/exec/scp and link operations are refused. Auth is by password or SSH public key (keys uploaded by the player to `.authorized_keys` in their home directory; the character must exist); the ed25519 host key is auto-generated at `ssh_host_key_file` on first start and never silently regenerated. Depends on small locally-defined `Authenticator`/`Authorizer` interfaces rather than the concrete types.

- **Authentication** (`pkg/authentication/`): Multi-hash password verification supporting both legacy Unix crypt (DES-based) and modern Argon2id (PHC format). Uses constant-time comparison and always performs hash verification even for non-existent users to prevent timing attacks and user enumeration. The `MultiVerifier` tries each hash algorithm in sequence.

- **Authorization** (`pkg/authorization/`): Hierarchical permission system that parses the MUD's `access.o` file containing an LPC-serialized access control tree. Permissions flow down the directory tree with inheritance, unless explicitly revoked. Uses cached access trees with configurable TTL. Supports permissions: Revoked, Read, Write, Grant (implying all lower permissions).

- **LPC Parser** (`pkg/lpc/`): Parses LPC (Lars Pensjo C) serialized object format used by LPMuds. Handles mappings (key-value pairs), arrays, strings, integers, and nested structures. Critical for reading both character files and the access control tree.

- **User Management** (`pkg/users/`): Loads and parses MUD character files containing LPC-serialized player data. Extracts username and password hash from character objects. Uses `FileSource` for reading from disk with caching support.

- **Logging** (`pkg/logging/`): Dual logging system with separate access logs (FTP operations) and application logs (server events). Uses structured logging with key-value pairs. Log level configurable via config file.

### Key Integration Points

The server directly reads MUD data files:
- **Character files** (`character_dir_path`): LPC-serialized objects containing player data including password hashes. One file per player named by username.
- **Access tree** (`access_file_path`): LPC-serialized hierarchical permission structure (`access.o`) defining per-user, per-directory access rights.
- **Caching strategy**: Both character data and access trees are cached in-memory with configurable TTL to minimize disk I/O. Cache is thread-safe with read-write mutexes.

### Data Flow

1. **FTP Connection**: Client connects → TLS negotiation (if configured) → authentication required
2. **Authentication**: Username provided → character file loaded and parsed → password hash extracted → multi-hash verifier attempts Unix crypt then Argon2id → user object cached
3. **Authorization**: File operation requested → path normalized → access tree traversed from root to target → permissions resolved with inheritance → operation allowed/denied
4. **File Access**: All file operations are jailed within `ftp_root_dir`. User home directory follows `home_pattern` (e.g., `players/{username}`).

### Status File Monitoring

Optional health monitoring feature that writes status files for MUD integration:

**Files created** (in `status_dir` if configured):
- `last_start` - Written once at startup with timestamp, PID, and version
- `running` - Updated every 10 seconds with live metrics (connections, memory, goroutines, uptime)
- `last_stop` - Written on graceful shutdown with reason and uptime

**Crash detection**: MUD can detect daemon crashes by checking if `running` is stale (>60s old) without corresponding `last_stop` update.

**File format**: Simple `key: value` pairs for easy LPC parsing.

**Signal handling**: Daemon responds to SIGTERM/SIGINT with graceful shutdown, writing `last_stop` with appropriate reason.

### Security Considerations

- **Timing attack protection**: Authentication always performs hash verification even for non-existent users
- **TLS support**: Optional FTPS with certificate and key configuration
- **Passive mode IP verification**: Optional check that data connection IP matches control connection
- **Permission inheritance**: Authorization respects MUD's hierarchical access control
- **Chroot-like behavior**: All paths jailed within configured FTP root directory
- **Secure logging**: Password hashes are never logged, even in debug mode