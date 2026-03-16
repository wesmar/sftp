Secure FTP Plugin
Copyright (C) Marek Wesolowski

Help:
- Open sftpplug.chm for full documentation.
- You can also open help from the plugin connection dialog via the Help button.

Installation:
- Open this ZIP in Total Commander and press Enter on the archive.
- Confirm plugin installation when prompted.
- Total Commander selects the correct architecture (x64 or x86) automatically.

Package contents:
- sftpplug.wfx64 (64-bit plugin binary)
- sftpplug.wfx   (32-bit plugin binary)
- sftpplug.chm   (offline help)
- sftp.php        (PHP Agent for HTTP transfer mode)
- pluginst.inf    (TC auto-install descriptor)
- readme.txt

Important:
- No external libssh2.dll or VC++ Redistributable required.

Highlights:
- SFTP + SCP support
- Shell transfer fallback for restricted hosts
- Jump Host / ProxyJump for bastion-routed SSH sessions
- PHP Agent (HTTP) transfer mode for hosts without SSH account access
- PHP Shell (HTTP) pseudo-terminal for remote command execution
- LAN Pair for direct Windows-to-Windows local network pairing
- Session import from PuTTY, WinSCP, and KiTTY Portable
- PPK/PEM key support
- Password manager integration (TC master password)
- 15-language localization (auto-detected from Total Commander settings)
