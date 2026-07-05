What's new in the file transfer server (1.x to 2.1)

- SFTP access. Connect with any SFTP client using your character name and password, not just plain FTP. Transfer only, no shell.
- FTP and SFTP permissions now match the MUD. The server used to deny some things the game allows; those cases are fixed.
- Broad access grants now reach the folders beneath them.
- Directories that are readable by default in the MUD are now readable over FTP.
- open/ directories work, including /d/<domain>/open: you can list them and download the files inside.
- An explicit grant in your own access map wins over the general rules.
- Uploaded files no longer land with wide-open permissions.
- Login names are validated so a crafted name cannot escape the character directory.
- Metadata changes such as chmod and rename are logged, and the connection limit is enforced.
- Malformed or half-written data files fail gracefully instead of crashing the daemon.

Note: with permissions matching the MUD, listing the bare root "/" may differ slightly for a few users. You start in your home directory at login, so it rarely comes up.
