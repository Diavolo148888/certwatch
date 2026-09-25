# certwatch

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-9cf)

**TLS certificate watchdog — expiry countdown, self-signed detection, weak-key alerts, hostname/SAN verification.**

Point it at one host or a fleet list and know immediately: what expires soon,
what's self-signed, what's on a weak key or deprecated TLS version, and what
cert doesn't actually cover the hostname it's serving.

Zero dependencies — pure Python `ssl`/`socket` from the standard library.

## Features

- ⏳ **Expiry tracking** — days remaining per host, configurable warning window, exit code reflects health
- 🔏 **Self-signed detection** — verifies against system CA roots; flags trust failures explicitly
- 🔑 **Key & signature strength** — RSA < 2048 bits, weak SHA-1/MD5 signatures flagged
- 🌐 **Hostname/SAN coverage** — wildcard-aware matching, mismatch warnings
- 📋 **Fleet mode** — `watch` a file of `host[:port]` lines, JSON report output
- 📦 **Zero dependencies** — Python 3.9+ standard library only

## Install

```bash
git clone https://github.com/USERNAME/certwatch.git
cd certwatch
```

## Usage

```bash
# Single host
python3 certwatch.py check example.com

# Custom port + tight warning window
python3 certwatch.py check mail.internal.lan --port 8443 --warn-days 14

# Fleet watch with JSON report
cat hosts.txt
#   api.example.com
#   mail.example.com:993
#   dev.internal.lan:8443
python3 certwatch.py watch hosts.txt --warn-days 21 --json report.json
```

### Sample output

```
✅ github.com:443 — OK
    subject:  github.com
    issuer:   Sectigo Limited
    expiry:   2027-01-15T00:00:00+00:00  (72 days left)
    SANs:     github.com, www.github.com
    key:      RSA 2048 bits
    TLS:      TLSv1.3

⚠️  dev.internal.lan:8443 — WARN
    ...
    ! certificate is self-signed (issuer == subject)
    ! hostname 'dev.internal.lan' not covered by certificate names (localhost)
```

Exit codes: `0` all ok · `1` any warn/crit/error — safe for cron/CI use.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

Live integration tests: real TLS endpoints (skipped gracefully offline) plus
a local self-signed HTTPS server spun up on an ephemeral port for the
self-signed detection scenario.

## License

MIT — see [LICENSE](LICENSE).
