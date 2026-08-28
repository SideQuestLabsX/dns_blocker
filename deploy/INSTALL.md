# dns_blocker release package

A DNS filtering and forwarding daemon for one architecture and one profile. The
package holds everything an install needs, so it needs no source checkout.

| File | What it is |
|---|---|
| `dns_blocker` | The daemon, static musl |
| `dns_blocker.check` | Health probe. Resolves a known name against `127.0.0.1:53` and exits 0 or non-zero |
| `dns_blocker.service` | systemd unit, systemd 247 or later |
| `install.sh` | Copies the files into place |
| `make-trust-bundle.sh` | Writes the TLS trust anchor. Encrypted packages only |
| `trust-bundle.env` | The cap and the host list this build was compiled with. Encrypted packages only |
| `LICENSE` | This project's own terms, The Unlicense |
| `THIRD_PARTY_LICENSES.md` | Terms of the code linked into the binary |
| `SHA256SUMS` | Digest of every file above |

The `minimal` profile forwards over plaintext DNS. The `encrypted` profile
forwards over DoH and needs a trust bundle before it starts.

## Verify and install

```sh
sha256sum -c SHA256SUMS
sudo sh install.sh
```

`install.sh` checks the digests itself and refuses to install a package that
does not match. It writes:

| Path | Contents |
|---|---|
| `/usr/local/sbin/dns_blocker` | The daemon |
| `/usr/local/sbin/dns_blocker.check` | The probe |
| `/etc/systemd/system/dns_blocker.service` | The unit |
| `/etc/dns_blocker/` | Runtime configuration, created empty |
| `/usr/local/lib/dns_blocker/` | The license files and the trust tool of an encrypted package |

Pass `--destdir DIR` to stage the same layout under another root.

## The trust bundle, encrypted packages only

The daemon parses concatenated DER and maps the file under a 16 KiB cap, so a
system CA store is refused by size. The tool collects only the roots the
configured endpoints chain to, which is about 3 KB from 4 roots today:

```sh
sudo sh /usr/local/lib/dns_blocker/make-trust-bundle.sh /etc/dns_blocker/ca.der
```

It needs `openssl` and outbound HTTPS, and it verifies every configured host
against the result before writing it.

Install the bundle before the first start. The unit restarts on failure, so a
daemon without a bundle fails several times a second until systemd stops trying.

**Roots rotate.** Generate the bundle again whenever the blocklist sync and the
DoH lookups begin failing together, because one stale bundle breaks both and
each reports only a TLS failure. Restart the daemon afterwards.

## Start

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dns_blocker
dns_blocker.check
```

Local names go in `/etc/dns_blocker/hosts`, in the format of `/etc/hosts`. The
daemon starts without that file.

The unit sends `stdout` to `/dev/null`. That stream carries one line per
answered query and names every domain every device on the network resolved. Set
`StandardOutput=journal` in a drop-in to keep it. `stderr` carries the
operational messages and reaches the journal either way.

## Under `init`

[`init`](https://github.com/SideQuestLabsX/init) supervises the daemon as a
generic task and needs none of the systemd files:

```sh
install -Dm755 dns_blocker /tasks/always/dns_blocker
install -Dm755 dns_blocker.check /tasks/always/dns_blocker.check
install -dm755 /etc/dns_blocker
```

Port 53 and the query stream are per-task settings in `init`'s `config.h`. See
the project `README.md`.

## Remove

```sh
sudo systemctl disable --now dns_blocker
sudo rm -f /etc/systemd/system/dns_blocker.service
sudo rm -f /usr/local/sbin/dns_blocker /usr/local/sbin/dns_blocker.check
sudo rm -rf /usr/local/lib/dns_blocker
sudo systemctl daemon-reload
```

`/etc/dns_blocker` holds the trust bundle and the local names, so it is left
alone.
