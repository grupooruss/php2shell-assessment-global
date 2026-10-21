#!/usr/bin/env python3
"""PHP2Shell exposure triage (CVE-2026-109618 / CVE-2026-109619).

Read-only, non-exploit inventory for explicitly authorized environments.
Requires Python >=3.9. Standard library only.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import glob
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib import error, parse, request

CVES = ("CVE-2026-109618", "CVE-2026-109619")
VERSION_RE = re.compile(r"(?<!\d)(\d{1,2})\.(\d{1,2})\.(\d{1,3})(?:[.-](RC\d+|alpha\d+|beta\d+))?", re.I)
PHP_BANNER_RE = re.compile(r"\bPHP\s*[/ ]\s*(\d{1,2}\.\d{1,2}\.\d{1,3}(?:[.-](?:RC|alpha|beta)\d+)?)", re.I)
EOL_BRANCHES = {f"{major}.{minor}" for major in (5, 7) for minor in range(0, 10)} | {"8.0", "8.1"}
SUPPORTED_BRANCHES = {"8.2", "8.3", "8.4", "8.5"}
FIELDS = ["timestamp_utc", "asset", "method", "php_version", "version_confidence", "status", "priority", "evidence", "recommendation", "http_code", "observed_url", "distro_package", "notes", "cve_ids"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_version(value: str) -> str | None:
    match = VERSION_RE.search(value or "")
    return match.group(0) if match else None


def numeric_version(value: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(value or "")
    return tuple(int(match.group(i)) for i in (1, 2, 3)) if match else None


def load_advisory(file_path: Path) -> dict[str, Any]:
    doc = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("advisory.json must specify schema_version=1")
    if doc.get("release_status") not in ("pending", "published"):
        raise ValueError("release_status must be 'pending' or 'published'")
    fixed = doc.get("minimum_fixed_versions")
    if not isinstance(fixed, dict):
        raise ValueError("minimum_fixed_versions must be a JSON object")
    if fixed:
        if doc["release_status"] != "published" or not str(doc.get("vendor_fix_reference") or "").startswith("https://"):
            raise ValueError("To use fix thresholds, set release_status=published and provide an official HTTPS reference")
        for branch, version in fixed.items():
            if branch not in SUPPORTED_BRANCHES or numeric_version(str(version)) is None:
                raise ValueError(f"Invalid branch or fixed version: {branch}={version}")
            if ".".join(str(x) for x in numeric_version(str(version))[:2]) != branch:
                raise ValueError(f"Version {version} does not belong to branch {branch}")
    return doc


def classify(version: str | None, advisory: dict[str, Any], confidence: str = "") -> tuple[str, str, str]:
    if not version:
        return ("NO_VERSION_OBSERVED", "REVIEW", "Confirm PHP and its version through authenticated inventory; HTTP headers may conceal it.")
    parsed = numeric_version(version)
    if parsed is None:
        return ("UNPARSEABLE", "REVIEW", "Verify the version manually on the host.")
    major, minor, _ = parsed
    branch = f"{major}.{minor}"
    if branch in EOL_BRANCHES or major < 8:
        return ("EOL_UNSUPPORTED", "CRITICAL", "Migrate PHP to a supported branch, verify distributor security patches, and isolate the system if immediate remediation is not possible.")
    if branch not in SUPPORTED_BRANCHES:
        return ("BRANCH_NOT_ASSESSED", "REVIEW", "Check vendor support lifecycle and official advisory details; do not infer CVE exposure.")
    fixed = advisory.get("minimum_fixed_versions", {}).get(branch)
    if not fixed:
        return ("PENDING_VENDOR_MATRIX", "HIGH", "Prioritize inventory and prepare upgrades; no verified official fix threshold is configured in advisory.json.")
    installed_tuple = numeric_version(version)
    fixed_tuple = numeric_version(str(fixed))
    # Prerelease builds must not be equated to stable, fixed security releases.
    if re.search(r"(?:RC|alpha|beta)\d+", version, flags=re.I):
        return ("PRERELEASE_REVIEW", "HIGH", "Do not consider RC/alpha/beta prereleases fixed without explicit vendor confirmation.")
    if installed_tuple < fixed_tuple:
        return ("BELOW_OFFICIAL_FIX", "CRITICAL", f"Upgrade to {fixed} or later within the same branch, or verify a vendor-documented backport.")
    return ("MEETS_UPSTREAM_VERSION", "VERIFY", "Meets the upstream fix threshold; verify the installed package, possible backports, and PHP-FPM/web-server restart.")


def make_row(asset: str, method: str, version: str | None, evidence: str, advisory: dict[str, Any], **extras: str | int) -> dict[str, str]:
    status, priority, guidance = classify(version, advisory)
    data = {field: "" for field in FIELDS}
    data.update({
        "timestamp_utc": utcnow(), "asset": asset, "method": method,
        "php_version": version or "", "version_confidence": "HIGH" if method.startswith("local") or method == "inventory" else "LOW",
        "status": status, "priority": priority, "evidence": evidence,
        "recommendation": guidance, "cve_ids": ", ".join(CVES),
    })
    data.update({key: str(val) for key, val in extras.items() if key in FIELDS and val is not None})
    return data


class SameHostRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> request.Request | None:
        source = parse.urlsplit(req.full_url)
        dest = parse.urlsplit(newurl)
        if source.hostname != dest.hostname or dest.scheme not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def web_probe(target: str, advisory: dict[str, Any], timeout: float, allow_invalid_tls: bool) -> dict[str, str]:
    raw = target.strip()
    parts = parse.urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return make_row(raw, "http", None, "Invalid URL (use http:// or https:// without embedded credentials)", advisory, status="INPUT_ERROR", priority="REVIEW")
    if len(raw) > 2048:
        return make_row(raw[:120], "http", None, "URL exceeds the maximum supported length", advisory, status="INPUT_ERROR", priority="REVIEW")
    context = ssl._create_unverified_context() if allow_invalid_tls else ssl.create_default_context()
    opener = request.build_opener(SameHostRedirect(), request.HTTPSHandler(context=context))
    http_code = ""
    observed = raw
    last_error = ""
    headers: Any = {}
    used_method = "HEAD"
    # HEAD first. GET is only used when the response lacks a PHP version or HEAD is rejected.
    # No payloads, body processing, POST, exploitation, forced browsing, or authentication.
    for method in ("HEAD", "GET"):
        try:
            req = request.Request(raw, headers={"User-Agent": "GrupoOruss-PHP2Shell-Assessment/1.0 (authorized defensive inventory)", "Accept": "*/*"}, method=method)
            with opener.open(req, timeout=timeout) as res:
                http_code = str(res.status)
                observed = res.geturl()
                headers = res.headers
            used_method = method
            banner = " | ".join(str(headers.get(name, "")) for name in ("X-Powered-By", "X-PHP-Version", "Server"))
            match = PHP_BANNER_RE.search(banner)
            if match:
                version = normalize_version(match.group(1))
                names = [f"{name}: {headers.get(name)}" for name in ("X-Powered-By", "X-PHP-Version", "Server") if headers.get(name) and PHP_BANNER_RE.search(str(headers.get(name)))]
                return make_row(raw, f"http-{used_method.lower()}", version, "; ".join(names), advisory,
                                http_code=http_code, observed_url=observed,
                                notes="Unauthenticated indicator: proxies and headers can hide or misrepresent the version; this is not proof of RCE.")
        except error.HTTPError as exc:
            http_code = str(exc.code)
            used_method = method
            headers = exc.headers
            banner = " | ".join(str(headers.get(name, "")) for name in ("X-Powered-By", "X-PHP-Version", "Server"))
            match = PHP_BANNER_RE.search(banner)
            if match:
                return make_row(raw, f"http-{method.lower()}", normalize_version(match.group(1)), f"PHP detected in HTTP response headers (HTTP {http_code})", advisory, http_code=http_code, observed_url=observed,
                                notes="Unauthenticated header; confirm with trusted inventory.")
            if exc.code not in (405, 501) and method == "GET":
                last_error = f"HTTP {exc.code} without a PHP version indicator"
            elif exc.code in (301, 302, 303, 307, 308):
                last_error = "Redirect to another hostname or disallowed destination"
        except (error.URLError, TimeoutError, ValueError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
            break
    if last_error and not http_code:
        return make_row(raw, "http", None, "Connection failed", advisory,
                        status="PROBE_ERROR", priority="REVIEW", notes=last_error)
    return make_row(raw, f"http-{used_method.lower()}", None,
                    "No PHP version observed in HTTP response headers", advisory,
                    http_code=http_code, observed_url=observed,
                    notes="This does not mean PHP is absent. Confirm using server-side access. " + last_error)


def get_php_executables() -> list[Path]:
    found: set[str] = set()
    which_php = shutil.which("php")
    if which_php:
        found.add(str(Path(which_php).resolve()))
    patterns = ["/usr/bin/php*", "/usr/local/bin/php*", "/opt/plesk/php/*/bin/php", "/opt/remi/php*/root/usr/bin/php", "/opt/homebrew/bin/php*", "C:/php/php.exe", "C:/tools/php*/php.exe"]
    for pattern in patterns:
        for candidate in glob.glob(pattern):
            p = Path(candidate)
            if p.is_file() and (p.name == "php" or re.fullmatch(r"php\d+(?:\.\d+)?(?:\.exe)?", p.name, re.I) or p.name == "php.exe"):
                found.add(str(p.resolve()))
    return [Path(p) for p in sorted(found)][:100]


def local_probe(advisory: dict[str, Any]) -> list[dict[str, str]]:
    found = get_php_executables()
    if not found:
        return [make_row("localhost", "local-cli", None, "No PHP executables found in common locations or PATH", advisory,
                         notes="PHP-FPM or containers may be running a different PHP installation.")]
    rows = []
    for exe in found:
        try:
            proc = subprocess.run([str(exe), "-n", "-r", "echo PHP_VERSION;"], capture_output=True, text=True,
                                  timeout=5, check=False)
            version = normalize_version(proc.stdout)
            if proc.returncode != 0 or not version:
                rows.append(make_row(str(exe), "local-cli", None, "Unable to retrieve PHP_VERSION", advisory,
                                     status="PROBE_ERROR", priority="REVIEW", notes=proc.stderr[:180]))
            else:
                rows.append(make_row(str(exe), "local-cli", version, "PHP_VERSION from CLI without loading php.ini (-n)", advisory,
                                     notes="The PHP CLI version does not establish the runtime version used by PHP-FPM, Apache, hosting, or containers."))
        except (OSError, subprocess.TimeoutExpired) as exc:
            rows.append(make_row(str(exe), "local-cli", None, "Error checking the executable", advisory,
                                 status="PROBE_ERROR", priority="REVIEW", notes=str(exc)[:180]))
    return rows


def inventory_probe(file_path: Path, advisory: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"asset", "php_version"}.issubset(set(reader.fieldnames)):
            raise ValueError("Inventory CSV must include asset and php_version columns")
        for i, rec in enumerate(reader, start=2):
            if i > 2001:
                raise ValueError("Batch limit exceeded: maximum 2,000 inventory entries")
            asset = (rec.get("asset") or "").strip()
            raw = (rec.get("php_version") or "").strip()
            if not asset:
                continue
            rows.append(make_row(asset, "inventory", normalize_version(raw), f"Inventory version: {raw or 'unknown'}", advisory,
                                 distro_package=(rec.get("distro_package") or "")[:120],
                                 notes=(rec.get("notes") or "")[:300] + " | Verify the effective service runtime version and any vendor backports."))
    return rows


def save_reports(out_base: Path, rows: list[dict[str, str]], advisory: dict[str, Any]) -> tuple[Path, Path]:
    out_base.parent.mkdir(parents=True, exist_ok=True)
    csv_path = Path(str(out_base) + ".csv")
    json_path = Path(str(out_base) + ".json")
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "tool": "Grupo Oruss - PHP2Shell Assessment", "generated_utc": utcnow(),
        "cves": list(CVES), "advisory_status": advisory["release_status"],
        "matrix_reference": advisory.get("vendor_fix_reference") or None,
        "disclaimer": "Inventory only; not an exploitability test. Missing PHP version headers do not mean PHP is absent.",
        "results": rows,
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return csv_path, json_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defensive PHP2Shell exposure assessment; no exploit payloads. Authorized systems only.")
    parser.add_argument("--url", action="append", help="Authorized URL; repeat for multiple targets")
    parser.add_argument("--urls-file", type=Path, help="Text file containing one authorized URL per line")
    parser.add_argument("--local", action="store_true", help="Check PHP CLI versions installed on this machine")
    parser.add_argument("--php-version", help="Assess a PHP version obtained from an authenticated source")
    parser.add_argument("--asset", default="manual-asset", help="Asset name associated with --php-version")
    parser.add_argument("--inventory-csv", type=Path, help="Authenticated inventory CSV with asset,php_version columns")
    parser.add_argument("--advisory", type=Path, default=Path(__file__).with_name("advisory.json"), help="Official vendor fix matrix configuration")
    parser.add_argument("--out", type=Path, default=Path("reports/php2shell-assessment"), help="Output prefix for CSV and JSON reports")
    parser.add_argument("--timeout", type=float, default=6.0, help="Timeout per request in seconds (default: 6)")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay between URLs in seconds (default: 0.25)")
    parser.add_argument("--insecure", action="store_true", help="Allow invalid TLS certificates; authorized test environments only")
    args = parser.parse_args(argv)
    if not any((args.url, args.urls_file, args.local, args.inventory_csv, args.php_version)):
        parser.error("Specify --url, --urls-file, --local, --inventory-csv, or --php-version")
    if not 0.5 <= args.timeout <= 60 or not 0 <= args.delay <= 60:
        parser.error("Timeout must be between 0.5 and 60; delay must be between 0 and 60")
    try:
        advisory = load_advisory(args.advisory)
        rows: list[dict[str, str]] = []
        targets = list(args.url or [])
        if args.urls_file:
            targets.extend(line.strip() for line in args.urls_file.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        if len(targets) > 2000:
            parser.error("Maximum 2,000 URLs per run")
        # Preserve order but skip exact duplicates.
        seen = set()
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            rows.append(web_probe(target, advisory, args.timeout, args.insecure))
            if args.delay:
                time.sleep(args.delay)
        if args.local:
            rows.extend(local_probe(advisory))
        if args.php_version:
            rows.append(make_row(args.asset, "inventory", normalize_version(args.php_version),
                                 f"Operator-provided version: {args.php_version}", advisory,
                                 notes="Confirm inventory evidence and the version of the running service."))
        if args.inventory_csv:
            rows.extend(inventory_probe(args.inventory_csv, advisory))
        csv_out, json_out = save_reports(args.out, rows, advisory)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Grupo Oruss | PHP2Shell Assessment | {len(rows)} asset(s)")
    print("NOTE: Version-based findings do not establish RCE exploitability.")
    for row in rows:
        print(f"[{row['priority']:<8}] {row['asset'][:65]:65} PHP {row['php_version'] or 'NOT OBSERVED':14} {row['status']}")
    print(f"CSV:  {csv_out.resolve()}")
    print(f"JSON: {json_out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
