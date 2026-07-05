What's new in the file transfer server (1.x to 2.1)

The headline is SFTP: you can now transfer files over an encrypted connection, not just plain FTP.

SFTP access

- Connect with any SFTP client using your character name and password.
- Traffic is encrypted, so your password and files no longer cross the network in the clear.
- Transfer only. No shell or command execution.

Permissions now match the MUD

The server used to be stricter than the game itself, so some things you could do in the MUD were denied over FTP. Those cases are fixed:

- Broad access grants reach the folders beneath them.
- Directories that are readable by default in the MUD are readable over FTP.
- open/ directories work, including /d/<domain>/open: list them and download the files inside.
- An explicit grant in your own access map wins over the general rules.

One shared core

- FTP and SFTP run through the same authorization code, so they enforce the exact same permissions. Neither protocol can allow something the other blocks.
- Access log lines are tagged with the protocol (ftp or sftp), so activity from each is easy to separate.

Security and reliability

- Uploaded files no longer land with wide-open permissions.
- Login names are validated so a crafted name cannot escape the character directory.
- Metadata changes such as chmod and rename are logged, and the connection limit is enforced.
- Malformed or half-written data files fail gracefully instead of crashing the daemon.
