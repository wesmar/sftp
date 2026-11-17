# Test results

The latest full run before a release, on the maintainer's machine. Every
suite builds the plugin's own sources with `/W4 /WX`; how to run them is in
the README, section *Verification and Test Suites*.

**Run of 2026-11-17, version 10.3.1.0** - Visual Studio 2026 (MSVC 14.52,
toolset v145), Windows SDK 10.0.28000.0, OpenSSL 4.1.0, libssh2 1.11.1.

| Suite | x64 | x86 | arm64 |
|-------|-----|-----|-------|
| Build, `/W4 /WX` | passed | passed | passed (cross-compiled) |
| Unit tests | 40 cases, 325,538 checks, passed | 40 cases, 325,538 checks, passed | compiled; to be run on Windows on Arm |
| Dialog layout, 7 dialogs × 16 languages | passed | | |
| PHP Agent protocol (signatures, replays, staged bodies) | 26 checks, passed | | |
| PHP Agent through the plugin, 2 agent configurations | 35 + 35, passed | 35 + 35, passed | |
| SSH integration, OpenSSH on Ubuntu 26.04: SFTP / SCP / SCP-only / shell / text | 36 / 36 / 36 / 36 / 39, passed | 36 / 36 / 36 / 36 / 39, passed | |
| LAN Pair between two computers (2026-11-16) | passed | | |

The arm64 plugin is a native ARM64 image (machine `0xAA64`) with Control
Flow Guard, ASLR with high entropy and DEP, and exports the same 43
functions as the x64 one.

## LAN Pair between two computers

Two Windows 11 computers (build 26300) on a home LAN;
`tests\run-lanpair-remote-test.ps1`. Everything after the handshake is
AES-256-GCM, so the rates include the encryption.

```
  ok   pair with the password
  ok   list the drives
  ok   create the remote directory
  ok   upload 16 MiB: 27.8 MiB/s
  ok   list it back, UTF-8 name and size intact
  ok   download 16 MiB: 45.4 MiB/s
  ok   downloaded bytes equal the uploaded ones
  ok   rename
  ok   delete the file and the directory
  ok   second session on the stored keys, no password
  ok   a wrong password is refused: Wrong LAN Pair password, or the stored key no longer matches
  LAN PAIR REMOTE TEST PASSED
  cleaned up: firewall rule, program, files and test keys on both computers
```

## LAN Pair unit tests

```
lanpair3: SPAKE2 matches the RFC 9382 P-256 test vector
lanpair3: SPAKE2 with different passwords, or a bad share, agrees on nothing
lanpair3: handshake, then an encrypted stream both ways
lanpair3: a wrong or missing key gets no session
lanpair3: an altered, replayed or reordered frame ends the connection
lanpair3: session against a file server - files, stored keys, refusals
6 passed, 0 failed, 67 checks
```
