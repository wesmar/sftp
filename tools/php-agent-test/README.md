# PHP agent test bench

Two throwaway web servers running `src/agent/sftp.php` from this
repository — PHP 8.3 and PHP 7.4, the two ends of what the agent claims to
support — for testing the plugin's PHP Agent transport without a real host.

## Start

From this folder, on any machine with Docker:

```
docker compose up -d
```

| Service | URL for the session | Files land in |
|---|---|---|
| PHP 8.3 | `http://<host>:8083/sftp.php` | `data-php83/` |
| PHP 7.4 | `http://<host>:8074/sftp.php` | `data-php74/` |

`<host>` is `localhost` with Docker on the same machine as Total Commander,
otherwise that machine's address. Stop with `docker compose down`; the data
folders stay until deleted.

On a machine without this repository, copy `src/agent/sftp.php` next to
`docker-compose.yml` and change the two `../../src/agent/sftp.php` mounts to
`./sftp.php`.

## Session in Total Commander

- Transfer mode: **PHP Agent (HTTP)**
- Connect to: one of the URLs above
- Password: `test-psk-change-me` — the `TC_SFTP_AGENT_PSK` value in
  `docker-compose.yml`; change both together

The agent takes its password from that environment variable, so the file
needs no hash written into it and can be mounted unchanged. Plain HTTP is
fine here and nowhere else.

## Worth knowing

- The agent's root is the folder `sftp.php` sits in, so `sftp.php` itself
  shows in the panel. It is mounted read-only; deleting or overwriting it
  from the plugin fails, as it should.
- A case-only rename (`File.txt` → `file.txt`) only shows the
  case-insensitivity fix when the data folder lives on a case-insensitive
  file system — Docker Desktop on Windows or macOS. On a Linux host the two
  names are different files and the rename is an ordinary one.
- PHP errors go to the container log: `docker compose logs php83`.
