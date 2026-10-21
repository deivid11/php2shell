# GitHub publish — CVE-2026-109618

Separate repo recommended: `CVE-2026-109618` (covers 109619 in docs).

## About (Description)

```
Modular PoC for CVE-2026-109618 / CVE-2026-109619 (php2shell) — PHP session.upload_progress UAF. Check, smart exploit (618), optional 619 offsets. Authorized testing only.
```

**Topics:** `cve`, `cve-2026-109618`, `cve-2026-109619`, `php2shell`, `php`, `security-research`, `poc`

## First push (PowerShell)

```powershell
cd c:\shellflow\CVE-2026-109618
git init
git add .
git status
# Confirm: NO results.jsonl, NO Asset-Data.csv, NO lists/
git commit -m "Initial commit: php2shell modular PoC (CVE-2026-109618/109619)"
git branch -M main
git remote add origin https://github.com/KULLANICI/CVE-2026-109618.git
git push -u origin main
```

## Pre-push checklist

- [ ] `python -m unittest discover -s tests -t . -v` → OK
- [ ] `git status` → no scan artifacts (see `.gitignore`)
- [ ] README + EXPLOIT.md + SECURITY.md present
- [ ] No proxies, credentials, or full domain dumps in commit

## CI

Push triggers `.github/workflows/tests.yml` (Python 3.11 / 3.12, stdlib only).
