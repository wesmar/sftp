# Changelog

User-facing summary of changes in **SFTPplug (`wesmar/sftp`)**. Each version
corresponds to a build of `SFTPplug.zip`. Internal refactors, build-script
tweaks, and other developer-only changes are kept brief or omitted; the git log
has the full detail.

Release `10.3.0.0` reunites the upstream `wesmar/sftp` line with community
improvements from `zvldz/totalcmd_sftp`, `numbereleven-a/sftp`, and `bukephalos`.

## 10.3.0.0 — 2026-11-14

### Features

- **OpenSSL 4.1.0 + libssh2 1.11.1 backend.** Statically linked OpenSSL 4.1.0
  (PGP- and SHA-256-verified, `no-autoload-config`) replaces the external
  `argon2` submodule (PPK v3 Argon2id is now computed natively via OpenSSL).
- **Custom `sftp-server` command.** Sessions can specify an explicit remote
  SFTP subsystem/binary path (useful on OpenWrt and non-standard hosts).
- **Skip / Skip all / Cancel on batch download errors.** Multi-file copy
  operations now prompt with *Skip*, *Skip all*, or *Cancel* on read failures
  (localized across all 16 UI languages) instead of aborting the entire batch.
- **Per-Monitor V2 DPI, Mica titlebar, and dynamic language layout.** All plugin
  dialogs (`Connection`, `Jump Host`, `Proxy`, `Properties`, `Download Error`)
  scale cleanly across DPI changes and auto-size controls for all 16 languages.
- **Faster shell fallback uploads.** Multi-line `base64` chunking sends up to
  49,152 bytes per command on large files, cutting transfer overhead sharply.
- **Hardened C++20 build & automated test suite.** Built with `/std:c++20`,
  `/W4 /WX`, Control Flow Guard, and CET (`x64`), backed by unit tests
  (PPK v2/v3, text conversion, ECMA-48 terminal filter, LAN Pair crypto,
  wildcards), 16-language UI layout checks, and 5-mode SSH integration tests.

### Fixes

- **Heap buffer overflow in SCP text-mode download (`ConvertCrToCrLf`).**
  Expanded output now resizes safely instead of writing past the buffer on
  LF-dense files.
- **ECMA-48 terminal sequence filter.** `scponly` and `shell` fallback modes no
  longer lose lines on `OSC 3008` (systemd) or `ESC[?2004h` (bracketed paste)
  on modern Ubuntu/Fedora hosts.
- **Unicode filenames outside the system code page.** Remote paths no longer
  collapse non-codepage characters (e.g. Cyrillic, Polish) to `?`.
- **Overwrite reporting on upload.** Uploading an existing file without the
  overwrite flag now properly reports `FS_FILE_EXISTS` per the Total Commander
  WFX specification.
- **Shell fallback edge cases.** Fixed creating 0-byte files, missing remote
  files downloading as empty, and 1–2 byte duplication on transfer resume.
- **`FsInitW`-only host crash.** Guarded against null ANSI `LogProc` /
  `RequestProc` callbacks when Total Commander initializes via `FsInitW` only.
- **Empty public key field in `SftpAuthPubKey`.** Passes `nullptr` to libssh2
  so the public key is derived from the private key instead of failing on
  `fopen("")`.
- **Wildcard lists (text-mode extensions).** A pattern longer than 259
  characters no longer ends the process, and case is folded for every
  language, not only for ASCII (`*.ĄB` now matches `x.ąb`).
- **`ls -l` parsing in SCP-only mode.** Only symbolic links lose their
  ` -> target` part; a regular file whose name contains ` -> ` keeps it.
- **Post-login command.** Its output is shown whole, including non-ASCII text
  at the end of a line, and the progress dialog shows its text again.

### Security

- **Stack protection (`/GS`) is on.** The build had it switched off.
- **Remote paths are sent whole or not at all.** A path too long for its buffer
  used to be cut short, which can name its parent directory; it is now refused.
- **SOCKS proxies.** SOCKS4/SOCKS5 requests can no longer overrun their buffer;
  a SOCKS5 server refusing every authentication method is recognised, and a
  reply with an unknown address type or a long bound name is no longer
  misread as success.
- **Stored passwords.** A password whose DPAPI form exceeded 1024 bytes was
  silently saved with the old XOR obfuscation instead; one longer than 259
  characters was read back empty. Both now round-trip through DPAPI.
- **PuTTY keys.** The `.ppk` MAC is checked for unencrypted keys too, Argon2
  parameters are bounded, the rebuilt key is checked for consistency, and the
  decrypted key never touches the disk (it is handed to libssh2 from memory).
- **No configuration planting.** OpenSSL ignores `openssl.cnf` and the
  `OPENSSL_CONF` variable, so no file on the machine can change its behaviour.
- **Diagnostic log off by default**, and written to
  `%LOCALAPPDATA%\SFTPplug\sftpplug.log` instead of the shared `C:\temp`.

### Known limitations

- **LAN Pair traffic is not encrypted.** Pairing derives a shared key, but the
  transfers themselves travel in the clear: use LAN Pair only on a network you
  trust. Authenticated encryption is planned.
- **The PHP Agent client authenticates with the shared key in a request
  header.** `sftp.php` can verify HMAC-signed requests, but the plugin does not
  sign them yet: reach the agent over HTTPS only.

## 10.0.2.2 — 2026-11-03

### Features

- **`~/.ssh/config` as an import source.** `[Imports]\[OpenSSH]` lists
  every host of the OpenSSH client config and connects with what it says,
  resolved as `ssh <host>` would: `HostName`, `Port`, `User`,
  `IdentityFile`, defaults from `Host *` and other patterns, `Include`,
  and `ProxyJump` with one hop as the jump host. The config stays the
  place the settings live; nothing has to be copied. `ProxyCommand` and
  jump chains are refused, `Match` is skipped.
- **Imports follow their sources without `[Refresh]`.** Opening a source
  folder notices when the program's files or registry keys changed since
  the last look — and on the first look after Total Commander starts — and
  re-reads them, in the auto-detected location and in the ones added by
  hand. A location that has gone missing keeps its sessions, as before. A
  host key confirmed for an imported session survives the re-read while
  the host stays the same.
- **Owner, group and permissions in the file list.** The plugin now
  offers custom columns — owner, group, permissions (`rwxr-xr-x`), octal
  (`0755`) and link target — and a default view with the first three next
  to size and date, which Total Commander picks up on its own. Values come
  from the directory listing in both SFTP and SCP mode; a server that
  sends no names shows numeric ids.
- **Alt+Enter on a remote file shows its properties**: path (with the
  link target), owner, group, permissions, size and date from the
  listing, and below them the server's own `stat` reply. Without a shell
  on the server, the SFTP attributes stand in for it. Translated into all
  languages.
- **Host key fingerprints are SHA256**, in the form OpenSSH prints, so
  they can be compared with `ssh-keygen -lf` on the server. The
  confirmation shows MD5 below it. A fingerprint stored by an earlier
  version (MD5) still matches and is rewritten as SHA256 on the next
  connection, without asking. The same for jump hosts.
- **Imported sessions that go through a jump host now come with it.** A
  WinSCP tunnel, a SecureCRT session firewalled through another session,
  and a PuTTY session using "SSH to proxy and use port forwarding" import
  with the jump host filled in — connect straight from `[Imports]` or copy
  with F5. The jump host's password is asked for on connect, as is the
  target's. Still refused: a jump host that itself goes through a proxy or
  another jump host, a WinSCP tunnel combined with a proxy, and
  command-driven proxies (Telnet, local command).

### Fixes

- **"Log full directory listings" works in SCP mode**: the raw `ls -la`
  lines go to the log window, as the server's long entries already did in
  SFTP mode.
- **SCP mode: names with spaces or quotes are listed as they are.** GNU
  `ls` writing to a terminal wraps such names in quotes (`'a b'`), which
  then appeared in the panel and led nowhere.
- **SCP mode shows dates and permissions.** The listing kept only names
  and sizes, so every row had an empty date. Dates now come from `ls`
  run in English and UTC, whatever the server's locale and time zone, and
  the permissions reach Total Commander as they do in SFTP mode.
- **Uploads no longer spin a CPU core while waiting for the server.**
  When the connection could not take more data yet, the plugin polled the
  socket in a tight loop instead of waiting for what libssh2 was actually
  waiting on.
- **A one-time code is not reused as the password.** With two-factor
  login, an answer to a verification-code prompt was kept as the session
  password and sent again on a reconnect or a background transfer. Only
  answers to password prompts are kept now.
- **Symbolic links show as links in SFTP mode too**, instead of with the
  length of their target as a size.
- **Changing permissions with Alt+A works.** The command went out with
  the path in Windows form, failed on the server, and was reported as
  done. Over SFTP the mode is now set through the protocol, so it also
  works on servers without a shell; SCP mode runs `chmod` and reports its
  failure.
- **A jump host with no saved password now asks for one** instead of
  failing the login without a word.
- **An idle connection is no longer dropped by a router or firewall in
  between.** The plugin turns on TCP keepalive for the server socket and
  the jump host socket, so the link stays open after a minute of silence.

## 10.0.2.1 — 2026-11-02

### Features

- **An imported session that needs a proxy or a bastion no longer
  connects without one.** Sessions arriving from SecureCRT, PuTTY,
  KiTTY, WinSCP and FileZilla carry only the fields the plugin can
  reproduce, and a proxy, jump host or tunnel was not among them — so a
  session that reached its host through one connected **straight to the
  target** instead, which looks like success whenever the target also
  answers from outside. Such a session now says what is missing and
  refuses to connect or to be copied into your own list. `F3` still
  shows its settings: the file it opens names the missing route, and the
  plugin refuses to import that file back.

- **An HTTP or SOCKS proxy from PuTTY, KiTTY, WinSCP, FileZilla or
  SecureCRT comes along when the session is copied.** FileZilla keeps one
  proxy for the whole program, so it comes along with every site that
  does not bypass it. SecureCRT keeps its proxies as firewall records; a
  session that tunnels through another SecureCRT session, or names a
  record that no longer exists, is still refused. `F5` from `[Imports]` into your own list
  points the new session at a matching entry in `[Proxies]`, reusing one
  with the same type, address and user name or adding one. Copying it
  out to a file writes the proxy into the file, and dropping that file
  back onto the plugin resolves it the same way. The proxy password stays
  behind and is asked for on the first connection. Connecting straight
  from `[Imports]` still refuses, and now says that `F5` brings the proxy
  along. Jump hosts and tunnels are still refused.

- **The help is one HTML page instead of a CHM.** The Help button now
  opens `SFTPplug-help.html` in your browser, and `Ctrl+F` searches
  every topic at once — the whole manual is a single page. This also
  ends a long-standing annoyance: a CHM that arrives inside a downloaded
  ZIP is blocked by Windows and opens blank, which is exactly how this
  plugin reaches people. Microsoft withdrew the only CHM compiler years
  ago and never replaced the format; a page in the browser is what the
  category turned into.

### Fixes

- **A malicious server can no longer attack the plugin through its SSH
  library.** libssh2 1.11.1, which the plugin is built on, had ten flaws a
  server could trigger. The worst, an out-of-bounds write while reading a
  packet's length (CVE-2026-55200), could let it run code on your machine;
  another tied up the CPU before any login (CVE-2026-55199). Some needed
  nothing more than connecting. libssh2 has fixed them but not yet
  released a version with the fixes, so the plugin carries the same
  backports Debian ships for 1.11.1.

- **The PHP Agent help now says how the password really travels.** It
  claimed every request was signed and the password never crossed the
  network. In fact the plugin sends the password in a header of every
  request, so only HTTPS protects it; over plain HTTP anyone on the path
  can read it and reuse it. The help, the README and `sftp.php` itself
  now say so and ask for HTTPS. They also say plainly that PHP Shell is
  not held to the agent's folder — it runs any command as the web server
  user — and `sftp.php` gains `AGENT_ALLOW_SHELL`: set it to `false` and
  the password gives file access only. It stays on by default, so
  existing setups keep working.

- **The PHP Agent can no longer be walked out of its folder.** A link
  inside the folder pointing elsewhere let an upload, a new folder, a
  rename or an unpacked archive land outside it, and a folder download
  pack files from outside; a neighbouring folder whose name merely began
  with the same letters (`html2` next to `html`) also passed the check.
  Deleting or renaming a link now acts on the link, not on what it points
  to, and the agent's own folder can no longer be removed — removing it
  with its contents used to take `sftp.php` along. Anonymous `PROBE`
  answers only what connecting needs, error replies no longer carry
  server paths, and a replaced file keeps its old content until the new
  one takes its name. Upload the new `sftp.php` (agent 1.0.2) to get
  these.

- **PHP Agent files land where the panel shows them.** With a port in
  the agent's URL (`http://host:8083/sftp.php`) the plugin took part of
  the URL for a folder, so every upload went into extra folders named
  after the port and the script, while the panel still looked like the
  top folder. A folder that does not exist was also shown with the top
  folder's contents instead of an error. And names with non-Latin
  letters were sent in the Windows code page instead of UTF-8: such a
  file arrived under a garbled name, and one put on the server by other
  means could not be opened. A name that began with the server's name
  or the script's (`example.com.zip`, `sftp.php.bak`) lost that part on
  the way, so the operation reached another file or none.

- **New folders appear on a PHP Agent with TAR stream on.** `F7`
  reported success without creating anything, and the empty folders of
  a copied tree were left out, since the archive carries files only.

- **Uploading folders into the PHP Agent's top folder with TAR stream
  on works.** The agent refused to unpack an archive into its own root
  and answered every such upload with an error.

- **An upload through the shell no longer claims to have worked when it
  did not.** Each piece of the file was counted as written the moment the
  server answered anything at all, so a missing tool, a read-only folder
  or a full disk still read as success — and an upload that was really a
  move then deleted the local original. The server's own answer is now
  read, and the size it ended up with is compared against what was sent.

- **A move and a cross-server copy ask before replacing a file.** Both
  went ahead silently: the destination was truncated without Total
  Commander getting the chance to ask, and a move destroyed the source on
  top of that. The check behind the question now treats a name as free
  only when the server says so outright: a check that could not run —
  a channel refused, permission denied — no longer reads as "no such
  file", a name with non-Latin letters on a shell-only server is no
  longer looked up encoded twice, and a PHP Agent destination is checked
  at all.

- **A file name can no longer run commands on the server.** On servers
  the plugin drives through a shell, the file's name went into the
  command line unquoted, so a name containing a semicolon or a backtick
  was read as syntax rather than as a name. Downloading such a file ran
  whatever it spelled out. Names are now quoted, as they already were
  everywhere else.

- **Deleting on such a server reports what really happened.** The shell
  echoes back the command it was given, and the plugin was reading that
  echo instead of the result — so a deletion the server refused was
  reported as done and the file quietly stayed. The same false success
  reached moves, which then looked like copies.

- **A deletion is refused outright when the path names no single file.**
  An empty or degenerate path — `/` among them — is rejected before any
  command is built, rather than handed to a shell that would take it
  literally.

- **F6 moves the file instead of copying it, in both directions.** The
  transfer ran and the original stayed where it was: the plugin was told
  this was a move and never acted on it, on downloads or on uploads.
  Each side of a move is removed by whoever owns it, and the plugin owns
  the far side of both — the file on the server when you move from it,
  the file on your disk when you move to it. If it cannot be removed,
  that is now said out loud rather than leaving you to notice the file
  twice. A move you resume keeps its source, since part of the result
  was there before and nothing vouches that it matches; the status line
  says so. Affects every server type, and has since the first release of
  the original plugin.

- **Copying a file within one session copies it.** Copying to another
  folder or name on the same server — `Shift+F5`, or `F5` between two
  panels open on the same session — renamed the file instead, so it was
  gone from where it had been. SFTP and PHP Agent sessions now copy it
  through this machine, since neither server offers a copy of its own;
  shell-only servers keep using `cp`; LAN Pair refuses rather than move
  the file.

- **LAN Pair: resuming and renaming are safe.** A resumed download wrote
  past the end of the partial file, leaving a gap of zeros, and a resume
  that failed deleted the partial file it was continuing. Renaming onto a
  name already taken replaced that file without asking; it now asks, as
  on other servers — provided both machines run this version, since an
  older peer still replaces. Moving a file up to a LAN Pair peer now
  takes the local file away, as it does elsewhere.

- **Removing a folder on a shell-only server removes only an empty
  one.** The plugin used `rm -rf` there, where SFTP servers refuse a
  folder that still holds files. Total Commander deletes the files
  itself first and relies on that refusal to keep anything that was
  skipped or failed — so after `F6` on a folder, or `F8` with a file
  answered "skip", those files were wiped along with the folder.

- **PHP Agent: an upload no longer takes up a leftover `.part` file
  unasked.** A `.part` left by an earlier upload was continued even
  without Resume — splicing its start, possibly from another file, onto
  this one, or at equal size turning it into the file without a byte
  sent. It is now continued only when you choose Resume. Renaming a file
  to the same name in other letter case on a Windows or macOS server no
  longer deletes it. Re-upload `sftp.php` to pick up the second fix.

- **A download that keeps breaking off at the same point gives up.** The
  automatic resume after a dropped connection retried for as long as it
  failed, so an error striking at one spot every time held the copy
  forever; it now stops once a retry adds nothing. And a command run
  through the shell — a rename or a copy on a shell-only server — that
  timed out before finishing no longer passes for a success.

- **The public-key field is labelled for what it is now for: an OpenSSH
  certificate.** Since the move to OpenSSL the public half of a key is
  derived from the private key file, so the field asking for "Public key
  file (*.pub)" invited a file the login does not need — and a private
  key put there was ignored. It now reads "Certificate (*-cert.pub),
  optional", in the session and jump-host dialogs alike, and the file
  picker looks for certificates first.

- **Logging in to a server that takes keys only says what is missing.**
  With no key to offer, the login used to end without a word; it now
  says that the server accepts only a key and the session has none. In
  "Use SCP for everything" mode the plugin did not even ask the server
  which logins it takes, and offered a password prompt the server would
  never accept — it now asks whenever no key or password is set. And a
  private key entered in the public-key field is used to log in, instead
  of being passed over.

- **Connecting to a server without SFTP ends, and says what to do.** A
  host that offers only a shell — dropbear on a camera or a router —
  never answers the request to start SFTP, and the plugin waited for that
  answer with no time limit, so the connection hung until cancelled. It
  now gives up after fifteen seconds and suggests turning on "Use SCP for
  everything (no SFTP)", which is what such a host needs.

- **On shell-only servers, names with non-Latin letters are written in
  UTF-8.** With "Use SCP for everything" on, the plugin never worked out
  the server's encoding and fell back to the Windows codepage, so a file
  whose name holds letters outside Latin arrived under a name nothing on
  the server could read — present, yet invisible in the panel and blank
  in a terminal.
  The encoding is now detected as it is for SFTP, and a system with no
  locale at all — busybox on a camera or a router — is taken to be UTF-8.
  A session saved with an explicit encoding keeps it; switch it to
  Auto-detect to have it checked.

- **A file that is not there no longer reads as scp missing.** With "Use
  SCP for data transfers" on, asking for a file the server does not have
  — which `Shift+F4` does for a new name, before the editor opens — showed
  "Cannot execute SCP… make sure SCP is installed", although scp had only
  said there was no such file. The plugin now checks over SFTP and leaves
  a status line instead; the dialog stays for scp really refusing.

- **Uploading with "Use SCP for data transfers" works.** Opening the
  upload channel asks the server to start scp, which on the plugin's
  non-blocking connection first answers "not ready yet"; that answer was
  taken for a refusal, so nearly every upload failed with nothing in the
  log to say why. It is now asked again until the channel opens, as
  downloads always did.

- **SCP and shell transfers check that they really finished.** With
  "Use SCP for data transfers" on, a download the server cut short or
  padded after a read error, and an upload it could not finish writing —
  a full disk, a quota — both passed for complete: the status scp sends
  at the end was never read. Downloads through the shell likewise took
  whatever arrived for the whole file. Both now hold the result against
  what the server announced and fail when it falls short, and a shell
  upload whose local file stops reading partway fails as well.

- **A resumed upload no longer writes over a larger file on the
  server.** When the remote file was longer than the local one, or the
  server did not report its size, resuming started writing from the
  beginning without cutting the file, so the old tail stayed behind and
  the upload reported success. It now fails instead. An upload whose
  local file stops reading partway — a network drive dropping out, say —
  also fails now, rather than passing for complete with a short copy on
  the server.

- **Servers without SFTP work outside the login directory.** On a host
  that offers only a shell — dropbear on a camera or a router, say —
  every operation was asked for relative to wherever the login left the
  shell: listing, creating a folder, deleting, and both directions of
  file transfer. The panel showed the home directory in place of `/`,
  nothing outside it could be reached, and uploads landed in the wrong
  place or nowhere. Paths are now sent as they are. An account confined
  to its own directory, which only understands paths relative to it, is
  not served yet: retrying a refused path relative to the login
  directory was tried and dropped, because it could aim a deletion at a
  file nobody meant.

- **Shell transfer mode works.** Such a server echoes back every command
  it is sent, and the plugin mistook a command too long for one terminal
  line for the end of the output — so a transfer read nothing and
  reported an empty file. Uploads could not work at all this way, since
  they carry the file's data inside the command. The echo is now switched
  off, and the terminal asked for is wide enough that nothing wraps.

- **Renaming and moving on such a server work.** The command was built
  from the Windows form of the path, backslashes and all, which a shell
  reads as a name no file has — and whatever the shell then answered was
  taken as success, so nothing moved and nothing complained.

- **Downloading from such a server works at all.** The plugin waited for
  an acknowledgement that `scp` never sends when it is the one supplying
  the file, and mistook the first byte of the file's header for a broken
  protocol. Every download failed with "SCP Protocol Error".

- **A failed listing or deletion on such a server no longer passes for
  success.** A directory that could not be read looked exactly like an
  empty one, and a file that could not be deleted was reported as
  deleted — in both cases the answer the shell gave was thrown away
  before anyone looked at it.

- **Copying files from one server to another works.** With a different
  session open in each panel, copying between them failed immediately
  with "Error downloading file!" — nothing was transferred and nothing
  was even attempted. No single SFTP operation can join two servers, and
  Total Commander does not step in for a plugin here, so the plugin now
  carries the file itself: down from one session and up to the other,
  with one progress bar across both halves. Copy, move, several files at
  once and whole folders all work, in both directions. LAN Pair sessions
  are not part of this and refuse. Two sessions that point at the same
  account on the same server refuse to copy a file onto its own path,
  which would cut it short — and, on a move, delete it. Broken since the
  first release of the original plugin.

- **The jump-host list says what its first entry means.** It read
  "(none)", which looks like "no jump host" — while it actually meant
  "use the settings typed into Jump...". It now reads "(manual)", and the
  help describes the choice between those settings and a saved session
  for the first time. The list is also disabled in PHP and LAN Pair
  modes, like the controls beside it: picking a session there used to
  switch the jump host on, and the Jump... button with it, in a mode that
  never uses one.

- **The jump-host dialog shows where its settings come from.** When a
  session supplies the jump host, the dialog used to be unreachable —
  the button simply went grey — while anything typed into it on an
  earlier visit was quietly ignored at connect time. That is what made
  an agent problem there so hard to place. The button now opens, the
  fields show the referenced session's host, user and key files, and a
  line at the top names the session they belong to. They cannot be
  edited, and pressing OK leaves this session's own jump settings alone.
  Its duplicate "use jump host" checkbox is gone; the one on the main
  dialog was always the one that counted.

- **A session copied to another machine takes its proxy along.** Copying
  a session out of the plugin writes an INI file; until now that file
  named the proxy by its position in your list, so the session landed
  elsewhere pointing at a different proxy, or at none — connecting
  straight to the host. The proxy is now described in the file, and on
  the way back an identical one already present is reused instead of
  being duplicated. Passwords still stay behind, on both the session and
  the proxy, and are asked for on the first connection.

- **Proxies have a folder of their own.** `[Proxies]` sits in the plugin
  root next to `[Imports]`: one row per proxy, `F7` to add, `Enter` to
  edit, `F8` to delete. A proxy still used by a session is not deleted —
  the sessions using it are named. Deleting a proxy no longer renumbers
  the others, so no session quietly ends up on a different proxy than
  the one it was given, and the connection dialog keeps just the list.

- **The help now says which way of disconnecting actually works.** Close
  a session from inside it, or press F8 on its row in `[Active
  Sessions]`. The toolbar button pressed from the plugin root or a magic
  folder leaves the connection open — Total Commander never tells the
  plugin about that click, so nothing can act on it.

- **The LAN Pair box on the connection dialog is translated.** It kept
  its English caption in every language, because it was the one group
  box missing from the table that drives runtime translation — the mode
  switch shows it in place of the file-rights box, so the dialog looked
  translated in three transfer modes and half-translated in the fourth.

- **A session whose jump host cannot be resolved says so once, not on
  every reconnect.** When the bastion is missing — a deleted reference,
  or the checkbox left on with nothing filled in — the plugin refuses to
  connect rather than going straight to the target. The refusal is right;
  raising a dialog for it on each of the reconnects that run mid-transfer
  was not. It now appears once per connection and goes to the status line
  after that.

- **The interface language is taken from the language file's name, not
  from the path leading to it.** Total Commander's `LanguageIni` may
  hold a full path, and the whole string was searched for a language
  code — so a folder in that path could decide the language before the
  file name was reached, and a `.lng` sitting under a directory called
  `Ita` came out Italian whatever it was named. Spotted in the
  numbereleven-a fork.

- **LAN Pair no longer accumulates a thread per client for the life of
  the session.** The accept loop meant to drop finished worker threads
  but tested them with `joinable()`, which stays true until a thread is
  joined — so nothing was ever dropped and every connection left one
  behind until disconnect. Spotted in the numbereleven-a fork.

- **A batch TAR download can no longer come out truncated.** The
  server-side packer ignored what `fwrite` reported and counted the
  bytes it had *read* instead, so a short write left the archive
  missing data while the padding was computed for the full length —
  every following file in it shifted out of place. Writes now repeat
  until the buffer is gone. Re-upload `sftp.php` to pick this up.
  Spotted in the numbereleven-a fork.

### Internal

- libssh2 stays on its 1.11.1 tag, with Debian's security backports
  applied at build time from `thirdparty/patches/libssh2-1.11.1/`. The
  patches are bound to that tag: a submodule on any other tag is refused,
  and a new tag gets none until someone decides it needs them.

- OpenSSL updated to 3.5.9. Its fixes since 3.5.7 sit mostly in QUIC,
  DTLS, CMS and CRL handling, which SSH does not reach; taken to stay
  current rather than for a known exposure.

- Drawing an `[Imports]` folder no longer copies the whole cached
  session list once per row; the cache answers whether a row is a
  session directly. On a source holding a few hundred sessions that was
  hundreds of thousands of string allocations per repaint.

## 10.0.2.0 — 2026-08-19

### Features

- **The old Import... button is gone; importing lives in `[Imports]`.**
  The button in the connection dialog, the checkbox picker it opened
  and the whole flow behind it have been removed now that the
  `[Imports]` folder covers all five sources. Everything the button
  did is available there: `Enter` on a session connects using the
  source program's settings, `F5` copies it into your own session
  list, and `Ctrl+A` followed by `F5` takes a whole source at once.
  The freed space went back into the dialog's bottom row — `OK` and
  `Help` had been squeezed narrow to fit the button and were tight
  for the longer translations.

- **Virtual sessions now show TC's connect-progress bar on Enter.**
  Before this pass, entering a session inside `[Imports]\...` did the
  SSH handshake silently inside our `FsExecuteFileW` handler — the
  panel just sat there for the couple of seconds it took to connect,
  with no visual indication that anything was happening. Now the
  handshake runs inside `FsFindFirstW`, the same call TC uses for
  real sessions, and TC decorates it with its native connect-progress
  dialog identical to what a real session shows on Enter. Two side
  benefits: connect failures now surface with TC's standard error
  message instead of failing silently, and entering a virtual session
  via a bookmark or a hand-typed path (previously broken) works
  correctly.

### Features from the beta cycle

- **`[Active Sessions]` magic folder.** A virtual folder appears in the
  plugin root whenever at least one saved session is connected.
  Entering it shows a flat list of every currently-open session by
  DisplayName (folder-nested sessions keep their slashes), with a
  `[Disconnect All]` row at the top. Press F8 on a row to disconnect
  that single session; F8 on `[Disconnect All]` closes everything at
  once. Pressing Enter on `[Disconnect All]` does the same and
  additionally drops you back to the plugin root in one gesture. The
  folder auto-hides when nothing is connected — no setup, no menu
  configuration. Useful when several sessions are open across TC tabs
  and you want to pick which one to close without tab-juggling.

- **`[Imports]` magic folder — SecureCRT sessions as live virtual entries.**
  A new `[Imports]` folder appears in the plugin root and lists every
  supported source program (SecureCRT is the first; PuTTY, WinSCP,
  KiTTY, FileZilla to follow). Inside a source folder:
  - `[Refresh]` re-scans and persists the session list to a cache next
    to `sftpplug.ini` — sessions survive TC restarts, appear
    immediately on the next launch.
  - `[Add custom location...]` lets you point the plugin at any
    portable install / backup folder in addition to the auto-detected
    location.
  - `[Manage custom locations]` lists what you've added; F8 removes an
    entry and prunes only its cached sessions.
  - Enter on a session connects using the cached settings.
  - F5 / drag onto another panel materialises the session into your
    own `sftpplug.ini` as a normal saved entry — from then on it
    behaves like any other session you created yourself. F5 / drag to
    a real filesystem path writes a portable INI snippet instead.
  - Cached sessions that become unreachable (source uninstalled, USB
    unplugged) stay visible until you explicitly remove them; refresh
    never prunes on failure to reach, only on an empty-but-reachable
    result.
  - Dropping a session-INI file onto the plugin root creates a new
    saved session in one gesture (reverse of the F5 export).

  SecureCRT specifics: reads `%APPDATA%\VanDyke\Config\Sessions\` and
  any custom path; passwords are intentionally not carried across —
  the standard interactive prompt kicks in on first connect, or you
  can save one via the Configure dialog. Non-SSH2 sessions are
  skipped.

- **`[Imports]\[PuTTY]` — PuTTY sessions as live virtual entries.**
  Same magic-folder UX as SecureCRT. Reads `HKCU\Software\SimonTatham\
  PuTTY\Sessions` (the standard registry key every PuTTY-compatible
  tool writes into — PuTTY itself, ExtraPuTTY, PuTTY CAC, and the
  tabbed runners mtPuTTY / SuperPuTTY that delegate storage back to
  PuTTY). `[Add custom location…]` accepts a portable
  `putty.reg` export file (the same one PortableApps'
  `PuTTYPortable\Data\settings\putty.reg` stores) — pick the file
  and its sessions merge into the source folder alongside the
  registry ones. Field mapping: `HostName` → `server`,
  `PortNumber` → server suffix, `UserName` → `user`,
  `PublicKeyFile` (`.ppk` / `.pem` / `.pub`) → key file, `AgentFwd`
  / `AuthAgent` → `useagent`, `LineCodePage` (`UTF-8`, `KOI8-R`,
  `KOI8-U`, `ISO-8859-N`, `CP1251`, `WIN-1252`, `Windows-1250`, and
  raw numeric codepages) → `utf8` / `codepage`, `EnterSendsCrLf` →
  `unixlinebreaks`. Proxy fields are intentionally not carried
  across for now — they need a separate cross-adapter materialise
  pass planned around Phase 4/5; PuTTY sessions behind a SOCKS/HTTP
  proxy import cleanly today but the proxy has to be re-entered
  manually on the materialised copy.

- **`[Imports]\[WinSCP]` — WinSCP sessions as live virtual entries.**
  Same magic-folder UX as PuTTY. Reads
  `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` (standard
  install) and any portable `WinSCP.ini` you point
  `[Add custom location…]` at. FSProtocol is honoured correctly:
  SFTP-only (2) and SFTP-with-SCP-fallback (1) open as regular
  SFTP sessions, SCP-only (0) sessions force the plugin's SCP
  transport (`scponly=1`, `scpfordata=1`, `unixlinebreaks=1`,
  `largefilesupport=0` — matches WinSCP's own SCP-mode default),
  and unsupported transports (FTP / WebDAV / S3) are silently
  hidden from the folder. Field mapping is otherwise identical to
  PuTTY. Passwords are intentionally not imported.

- **`[Imports]\[FileZilla]` — FileZilla sessions as live virtual
  entries.** Same magic-folder UX. Reads
  `%APPDATA%\FileZilla\sitemanager.xml` (standard install) and any
  portable `sitemanager.xml` you point `[Add custom location…]` at.
  Only `Protocol=1` (SFTP) is exposed; FTP / FTPS / WebDAV / S3
  entries are silently hidden. Nested `<Folder>` elements become
  nested subfolders in the panel (`Team/prod/host1`). Key files
  are picked up from `<Keyfile>` — including OpenSSH-style paths
  without an extension (`id_rsa`, `id_ed25519`), which FileZilla
  routinely writes because its fzsftp back-end reads OpenSSH PEM
  directly. Passwords are intentionally not imported. Host-key
  fingerprints from `hostkeys.xml` are not inherited either — TC
  shows its own TOFU prompt on first connect, same as for any
  other imported session.

- **`[Imports]\[KiTTY]` — KiTTY sessions as live virtual entries.**
  Same magic-folder UX. KiTTY is portable-first and has no canonical
  install path; the plugin probes three common locations in order
  (`%APPDATA%\KiTTY\Sessions\`, `%LOCALAPPDATA%\KiTTY\Sessions\`,
  `%USERPROFILE%\KiTTY\Sessions\`) and, as a last resort, resolves
  the KiTTY exe via the `HKCR\.kitty` file association registered
  by the KiTTY installer. If none match, the folder still appears
  once you add a portable directory through
  `[Add custom location...]` — pick either the `Sessions\` folder
  itself or the KiTTY install root (the adapter auto-descends when
  a `Sessions\` sibling of `kitty.exe` is present). Field mapping
  follows PuTTY (`HostName`, `PortNumber`, `UserName`,
  `PublicKeyFile`, `AgentFwd` / `AuthAgent`, `LineCodePage`,
  `EnterSendsCrLf`). Only `Protocol=ssh` entries appear;
  `Default%20Settings` template file is filtered out.
  **Passwords ARE imported** for KiTTY — deliberate exception to
  the "no password import" rule used for PuTTY / WinSCP / FileZilla,
  because autosave-password in KiTTY is an explicit user opt-in
  (not the default) and previous versions of this plugin's F11 flow
  always imported it. Decoded natively via the built-in
  `KittyDecrypt` (no external `kitty-decryptpassword.exe` helper
  needed) and re-wrapped with the plugin's own DPAPI obfuscation
  before it lands in the cache.

- **PPK ed25519 keys now work end-to-end.** Previously any imported
  or user-configured session pointing at an ed25519 `.ppk` failed
  auth silently (`PpkConverter` reported `unsupported_algorithm`;
  `SftpAuth` aborted with "Public-key auth aborted due to local key
  file error"). The converter now parses ed25519 PPK v3 blobs and
  emits a proper OpenSSH key container (`-----BEGIN OPENSSH PRIVATE
  KEY-----` — the same file format `ssh-keygen -t ed25519` writes),
  which libssh2 consumes directly through OpenSSL. Fix
  applies plugin-wide, not just to Import-related paths: hand-
  configured sessions with `privkeyfile=<...>.ppk` benefit too.
  RSA / ECDSA PPKs are unchanged. Encrypted-ed25519 PPKs and the
  Ed448 curve (PuTTY 0.75+ can write it) are not covered yet — open
  an issue if you need either.

### Fixes

- **The help row in the plugin root is named in your language.** Four
  translations carried a translated name and eleven still showed
  `F7 - help.txt`; all fifteen now match the interface language.

- **The `F7 - help.txt` text follows the plugin's language.** It was
  read straight from the compiled English resource, so the translations
  shipped in the `.lng` files never reached it. The file is UTF-8 now,
  with a byte-order mark so viewers read non-Latin text correctly.

- **F3 on the Quick Connection row no longer reports a download error.**
  It had no handler, so Total Commander tried to fetch the row from the
  server and failed. Both pseudo rows in the plugin root now show the
  plugin help, which is what they stand for.

- **Alt+Enter on a session inside `[Imports]` explains itself instead of
  doing nothing.** Imported sessions belong to the source program and
  are not editable here, but the key press was silently ignored. It now
  says so and points at `F3`, which shows the settings, and `F5`, which
  copies the session into your own list.

- **SecureCRT sessions pick up their key file the way the other sources
  do.** The path was taken from `Identity Filename V2` verbatim, so a
  `%USERPROFILE%`-style path stayed unexpanded and a `.pub` file landed
  in the private-key field. It now goes through the same expansion and
  public/private routing as PuTTY, WinSCP, FileZilla and KiTTY.

- **A long imported key path no longer arrives with its variables
  unexpanded.** Expansion used a fixed buffer and, when the result did
  not fit, silently handed back the original `%VAR%` text — which then
  failed at connect time with nothing pointing at the cause.

- **The `Session:` field is now just the session's name.** It used to be a
  dropdown of every saved session, and picking one loaded that session
  into the dialog — a session manager inside the window for editing one
  particular session. It had stopped working some releases ago, and while
  it worked it was a way to lose settings: choosing another session meant
  editing it under the name the dialog had opened with, so `OK` either
  refused with "session already exists" or saved one session's jump host,
  PHP, LAN-pair and encoding settings over another's. Sessions are chosen
  in the panel; the field names the session, and typing a different name
  renames it.

- **Saving a session under a name that already exists warns instead of
  replacing it.** Creating a session with a name already in use quietly
  overwrote that session from the connection dialog, and did nothing at
  all — no message, no session — when the name was typed at `F7`.
  Renaming onto a taken name already warned; all three paths now agree.

- **A passphrase you type to unlock a key is not offered to the server as
  a password.** A passphrase entered for a `.ppk` key was kept as the
  account password, so when key authentication then failed, the fallback
  sent that passphrase to the server as a login attempt. It now stays with
  the key. A password field holding a single unquoted value is still tried
  as both, since nothing says which it is — use the two-value form below
  to state it.

- **A password and a key passphrase stored together are read correctly.**
  The `"password","passphrase"` form was understood differently depending
  on which authentication method ran — one path used the second value as
  the account password, another as the passphrase, and the `.ppk` path
  ignored the split entirely and tried the whole field as a passphrase.
  The second value also came back with a stray trailing quote, so a
  passphrase stored this way never matched. One reading now applies
  everywhere: the first value is the account password, the second the key
  passphrase. This is also documented in the help file for the first
  time, and it now works for jump hosts as well. If you had relied on the
  previous order, swap the two values.

- **Changing a session's jump host no longer warns that the host key
  changed.** The fingerprint of the previous jump host stayed with the
  session, so pointing it at a different machine made the next connect
  compare the new host against the old one's key and report it as a
  change. Repointing the jump host now clears the stored fingerprint, and
  the machine is treated as first seen. A jump host taken from another
  saved session also no longer leaves its fingerprint behind in the
  session that referenced it.

- **Pageant authentication to a jump host works now.** If an SSH agent
  key was the only credential for the jump host, connecting failed
  immediately — the plugin never actually offered the key to the server.
  A saved key file or password for the jump host masked this, because
  the connection then succeeded through those instead. Reported and
  fixed by bukephalos (PR #2).

- **The jump-host session dropdown showed garbled text in translated
  builds, and its "(none)" entry did not work.** The list was filled
  through the ANSI window messages while the translations themselves
  are UTF-8, so any non-Latin caption came out as mojibake. The same
  mismatch broke the read-back: selecting the placeholder entry was
  interpreted as choosing a session literally named "(none)", so the
  plugin went looking for a jump host by that name instead of
  understanding that no jump host was wanted. Affected every language
  whose translation of "(none)" is not plain ASCII — Russian,
  Ukrainian, Japanese, Chinese and others.

- **Everything in the connection dialog is translated now.** The
  `Jump...` button had no string ID at all and stayed English in all
  15 languages. Twelve further strings — the jump-session dropdown
  entries, two jump-host error messages and the seven messages shown
  when a session INI is dropped onto the plugin — existed only in
  English. All are translated in every shipped language.

- **The jump-host row no longer overlaps itself in translated builds.**
  The row holds four controls — label, checkbox, session dropdown and
  button — but the code that arranges it only knew about three, and
  positioned the button directly after the checkbox text as if the
  dropdown were not there. English happened to land close enough to the
  designed position that it looked correct; any other caption length
  broke the row, either by stretching the checkbox across the dropdown
  or by pulling the button on top of it. The button is now anchored to
  the right edge and the dropdown gets the space between it and the
  checkbox. The Russian and Ukrainian checkbox captions were also
  shortened to just "Использовать" / "Використовувати", since the label
  immediately to their left already says which host is meant.

- **Unsupported Total Commander languages fall back to English.**
  Switching TC to a language the plugin ships no translation for left
  the plugin showing whichever language was selected before the
  switch, instead of reverting to English. Noticed with a Swedish TC,
  but it applied to every unsupported language. Note the plugin still
  reads the language once when it loads, so changing it in TC takes
  effect after restarting Total Commander.

- **The bundled help was months out of date.** The compiled `.chm` had
  not been regenerated since March because the build machine lacked
  the tool that produces it, so the build quietly shipped the old
  file. It now matches the current documentation — including the
  `[Imports]` folder, which had never been documented at all.

- **Imported sessions no longer lose encoding / line-ending
  auto-detection.** Every session materialised from an `[Imports]`
  folder was written with `utf8=0`, `unixlinebreaks=0` and
  `largefilesupport=0` pinned, even when the source program had no
  opinion on those settings. The plugin's own auto-detection was
  therefore permanently disabled for imported sessions — non-UTF-8
  servers showed mangled filenames, and the >2 GB capability probe
  never ran. The three fields now stay at their "auto" default
  unless the source program actually specifies a value.
- **WinSCP sessions with non-ASCII names now open.** A session named
  in Cyrillic, Greek, CJK, or anything else outside plain ASCII
  appeared in `[Imports]\[WinSCP]\` but silently failed on Enter —
  the plugin re-encoded the name using a narrower character set than
  WinSCP itself uses, so the lookup missed. Same fix covers names
  containing `/`, `?`, `*`, `"`, `<`, `>`, `|`, and a leading dot.
- **PuTTY and KiTTY sessions with punctuation in the name now open.**
  A session called e.g. `web01 (staging)` or `deploy@prod` was
  over-escaped on lookup and could not be found. The encoder now
  matches what PuTTY actually writes to disk — brackets, `@`, `+`,
  `=`, `;`, `#` and friends stay literal.
- **WinSCP workspace entries no longer show up as phantom sessions.**
  WinSCP stores saved window layouts under `Sessions\Workspaces\…`;
  these were listed as if they were real sessions and failed on
  Enter. Now filtered out, along with the unencoded
  `Default Settings` template row.
- **FileZilla: non-SFTP sites are hidden instead of failing on
  Enter.** FTP, FTPS, WebDAV and S3 entries from `sitemanager.xml`
  were listed in the folder and only rejected once you tried to open
  them. They are now filtered during the folder listing, matching how
  the WinSCP and KiTTY sources already behave.
- **Shift+F5 (same-panel copy) on a session or folder no longer
  throws you out of the plugin.** After a successful copy the
  plugin was posting `cm_RereadSource` unconditionally; for
  same-panel intra-plugin copy this races with Total Commander's
  own post-copy refresh and threw the user to the other panel's
  drive root. The extra refresh is now sent only for rename
  (`F6` / Move=TRUE), where our INI changes are invisible to TC
  and an explicit refresh is genuinely needed.

### Internal

- Decrypted passwords from FileZilla and KiTTY imports are overwritten
  in memory rather than left in freed buffers for a crash dump or the
  hibernation file to pick up — on the failure paths as well, where a
  half-decrypted buffer would otherwise survive. Best effort by nature:
  it covers the copy the adapter owns.

- Message boxes the plugin raises now go through one helper, which asks
  Total Commander to draw them (`RequestProcW`) and falls back to a bare
  `MessageBoxW` only where that callback is missing. Two of the three
  call sites were drawing their own.

- OpenSSL updated to 3.5.7, which carries seven CVE fixes including a
  high-severity use-after-free in `PKCS7_verify`. SSH does not reach
  the PKCS#7, CMS or QUIC code those mostly live in, but the ASN.1
  string-conversion overflow is on a path key and certificate parsing
  can take. libssh2 stays at 1.11.1 and argon2 at 20190702, both
  current.

- Built with the VS 2026 / MSVC v145 toolset, replacing VS 2022 and
  v143. OpenSSL, libssh2 and argon2 are rebuilt from source for every
  release, so they come from the new compiler too.

- Deleted the legacy import subsystem: `SessionImport.cpp` and its
  header, the session-picker dialog template, 41 resource IDs and 510
  lines of translation across the 15 shipped `.lng` files. Roughly
  2400 lines gone. Nothing shared was stranded — the folder picker,
  INI helpers, KiTTY decoder, DPAPI wrappers and PPK converter all
  keep independent callers in the adapter code.
- Session-import adapters share one set of primitives instead of
  carrying private copies: percent-encode / decode, registry string
  and DWORD readers, environment-variable expansion, key-file slot
  routing, and the cache hash all live in `ImportIoUtil` now. Removes
  roughly 200 lines of duplication across the five adapters and rules
  out the copies drifting apart.
- Removed `src/include/KittyDecryptDeploy.h` — an interface-only stub
  for deploying an external KiTTY password-decrypt helper. The
  decryptor is native C++ in the plugin, so no external binary was
  ever needed and nothing referenced the header.
- Removed `src/core/ConnectionDialogClass.cpp` (an unfinished class-extraction
  refactor inherited from upstream) and the duplicate `src/php/sftp.php` (the
  canonical PHP agent script lives at `src/agent/sftp.php`). Pure dead-code
  cleanup, no behaviour change.
- Removed the dead `2030-01-01` ZIP timestamp marker from `build.ps1`. It was
  inherited broken (the LastWriteTime write ran before the FileStream was
  released, so nothing was ever set), the purpose was never documented, and
  mtime does not survive `git checkout` anyway. Simpler build script.

## 10.0.1.4 — 2026-06-24

### Features

- **Saved sessions can be grouped into folders.** When you accumulate enough
  saved sessions that a flat list becomes unwieldy, you can put them into
  folders that show up alongside regular sessions in the plugin root:
  - **F7 inside a folder** creates the session in that folder automatically.
  - **F6 (rename)** is the universal "move" gesture — type a destination
    path that includes a folder (e.g. `\work\web1`) and the session moves
    there. F6 on a folder bulk-renames every session in it.
  - **F8** on a folder removes the folder and every session inside (TC
    asks for confirmation as usual).
  - **Drag-and-drop** between panels works for both sessions and folders.
  - Folders are *implicit*: a folder exists while at least one session
    lives under it. No "create empty folder" step, no orphan placeholders.
  - **Jump-host references survive rename and move.** If session B uses A
    as its jump host and you rename A (or move A into a folder), B's
    reference is updated automatically — the by-reference jump picker
    won't surface a "missing" marker.
  - Backwards compatible: existing flat session profiles keep working
    unchanged.

- **F3 / F4 on a saved session opens the Edit Session dialog.** Same dialog
  you've always been able to reach via Alt+Enter or RMB → Properties; F3/F4
  now bind to it from the keyboard. Works for sessions both at the plugin
  root and inside folders.

### Fixes & UX polish

- **Editing a session in a folder** (Alt+Enter / Properties / F3 / F4) now
  opens the dialog like for a root-level session. Previously the action
  fell back to TC's "download as file" path and produced an "Error
  downloading file" popup.
- **The padlock icon** for saved sessions is now shown for sessions inside
  folders too, not just at the plugin root.
- **Connecting to a session in a folder** works the same as connecting to
  one at the root — Enter resolves the session and lands you in its
  remote filesystem.
- **Copy / move / paste of folders** through TC no longer pops a spurious
  empty "New Connection" dialog mid-transfer. (The dialog used to appear
  because TC probes the destination path before creating it; the plugin
  now recognises this pattern.)
- The "WebDAV" leftover in dialog resource names was renamed to "Connection"
  for clarity — the plugin has not implemented WebDAV in years.

## 10.0.1.3 — 2026-05-17

### Features

- **Jump host by saved-session reference.** In the F7 connection dialog
  there is now a dropdown next to the Jump button that lets you pick an
  existing saved session as the jump host. Selecting a session links its
  network/auth settings by reference, so editing the jump session once
  propagates to every session that uses it as a jump (the OpenSSH
  `ProxyJump` model). Missing/deleted target sessions show up as
  `[!] name (missing)` markers in the picker.
- **Diagnostic status messages are prefixed with the session name**
  (`[session] Upload file: ...`). Useful when you have several connections
  open in different TC tabs and want to see which one is reporting status.

### Fixes & polish

- F3 / F4 on a saved session entry now opens the Edit Session dialog
  (alternative to Alt+Enter). 10.0.1.4 extended this to sessions inside
  folders; in 10.0.1.3 it works for root-level sessions only.
- `Get directory:` status lines use forward slashes to match the rest of
  the SFTP/SCP status output (was a stray backslash before).
- The plugin help text reachable from `[F7 = new connection]` mentions
  the F3/F4 shortcut.
- `build.ps1` no longer fails with a misleading "could not remove bin"
  warning when an indexer or AV holds the output directory open; it now
  only removes the zip artifact.

### Transparency

- The argon2 library (used internally for PuTTY PPK v3 key files) is now
  built from its public source instead of being shipped as a pre-compiled
  binary that came with the upstream codebase. Anyone reviewing the
  plugin can now see exactly what third-party code goes into the build.

## 10.0.1.2 — 2026-05-11

### Fixes

- **Server-side file handle leak.** Each transfer used to leave a handle
  on the server until the connection was closed; long-running sessions
  could eventually exhaust the server's per-connection handle limit.
  Handles now close deterministically after every transfer.
- **Disconnect no longer freezes Total Commander for several seconds.**
  When tearing down a session, the plugin used to spin on the libssh2
  cleanup path even when the network was already gone. Cleanup now
  bounds the wait.
- **CPU usage during transfers** is significantly lower. The wait loops
  around `EAGAIN` on libssh2 calls used to be busy spins; they now wait
  on the underlying socket and wake when data is actually ready.

## 10.0.1.1 — 2026-05-07

### Fixes

- **Public-key authentication** with only a private key configured (no
  public key field set) now works. Previously the plugin refused to try
  the key — the public component is computed from the private one
  internally.
- **Jump host (ProxyJump) stability.** Several scenarios that used to
  crash or hang the plugin are fixed: missing jump credentials, jump
  fingerprint validation edge cases, and disconnect during jump
  negotiation.

## 10.0.1.0 — 2026-05-07

### Features

- **Broader SSH algorithm support.** The plugin's SSH layer now runs on
  the OpenSSL crypto engine instead of the previous Windows-built-in
  backend. The user-visible effect is that modern host keys, key
  exchanges and ciphers — the ones many up-to-date OpenSSH servers
  require by default — are now supported, so connections that used to
  fail with "no matching algorithm" against newer servers go through.
