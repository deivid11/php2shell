# Security policy

## Purpose

Proof-of-concept for **CVE-2026-109618** / **CVE-2026-109619** (PHP `session.upload_progress` / php2shell research). For:

- Patch verification on systems you own
- Isolated lab reproduction (e.g. 0x4148 docker lab)
- **Authorized** penetration tests with written scope

Not for mass scanning or use against arbitrary internet hosts.

## Supported use

| Activity | Environment |
|----------|-------------|
| `check` | Owned / scoped staging |
| `exploit --chain 618` smart mode | Scoped; interprets weak signals only |
| `exploit --monitor` | **Lab** with `check_progress.php` |
| `exploit --chain 619` | Lab with known `--call` / `--dtor` offsets |

## Do not commit

- FOFA/asset exports (`*_Asset-Data.csv`), `results*.jsonl`, `lists/`, live proxy lists
- Customer domain lists or scan output

## Reporting

Product issues: [php.net security](https://www.php.net/security). PoC bugs: GitHub issues on this repo.

Authorized testing only. You are responsible for compliance with applicable law.
