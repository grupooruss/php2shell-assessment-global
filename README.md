# PHP2Shell — Defensive PHP Vulnerability Assessment

**Grupo Oruss / División 81** · 

A **non-intrusive inventory and remediation-prioritization tool** for the PHP security issues tracked as **CVE-2026-109618** and **CVE-2026-109619** (collectively reported as *PHP2Shell*). The tool collects version indicators and compares trusted runtime inventory against **vendor-verified patch thresholds**, once those thresholds are configured.

**No exploitation is performed.** The tool does not send RCE payloads, attempt authentication, modify remote systems, brute-force accounts, or claim to prove exploitability.

## Features

- **Authorized HTTP checks:** Assess individual URLs or batches via `HEAD`, with a `GET` fallback when no PHP version is disclosed. Checks HTTP headers only and does not inspect response bodies.
- **Local installation inventory:** Identify common PHP CLI binaries and query their versions. **The CLI version may differ from PHP-FPM, Apache, container images, or managed hosting runtimes.**
- **Trusted asset inventory:** Import `asset` and `php_version` records from CSV, with optional `distro_package` and `notes` columns.
- **Conservative classification:** Categorize unsupported branches, unidentified installations, versions pending official patch data, and versions above/below configured vendor thresholds.
- **Report generation:** Export machine-readable JSON and Excel-friendly UTF-8 CSV, including evidence, priority, and remediation guidance.
- **Zero third-party dependencies:** Python's standard library is sufficient.

## Quick start

### Requirements

- Python **3.9 or later**
- Windows, Linux, or macOS
- Permission to assess the target assets

From the extracted repository directory, open **PowerShell** on Windows:

```powershell
# Assess a permitted web application (headers only)
py -3 php2shell_assess.py --url https://app.example.org/ --out reports/web-app

# Assess several explicitly authorized endpoints
py -3 php2shell_assess.py --urls-file examples/targets.txt --out reports/batch

# Assess trusted inventory from a CSV file
py -3 php2shell_assess.py --inventory-csv examples/inventory.csv --out reports/inventory

# Query locally installed PHP CLI binaries
py -3 php2shell_assess.py --local --out reports/local

# Assess a PHP version identified through an authenticated inventory
py -3 php2shell_assess.py --php-version 8.4.26 --asset qa-server --out reports/qa-server

# Run automated tests
py -3 -m unittest discover -s tests -v
```

On Linux/macOS, replace `py -3` with `python3`.

**All hosts in `examples/targets.txt` and `examples/inventory.csv` are illustrative.** Replace them with assets that you own or are explicitly authorized to assess before running network checks.

### Command-line options

| Option | Description |
|---|---|
| `--url URL` | Assess one authorized URL; can be specified more than once. |
| `--urls-file PATH` | Read authorized URLs from a text file, one per line. |
| `--local` | Check PHP CLI binaries found on the local machine. |
| `--inventory-csv PATH` | Read a trusted PHP version inventory from CSV. |
| `--php-version VERSION` | Assess a version confirmed through another trusted source. |
| `--asset NAME` | Label used with `--php-version`. |
| `--advisory PATH` | Path to a vendor-verified advisory configuration JSON. |
| `--out PATH` | Output file prefix for `.csv` and `.json` reports. |
| `--timeout SECONDS` | HTTP request timeout, default `6`. |
| `--delay SECONDS` | Delay between URLs, default `0.25`. |
| `--insecure` | Disable TLS certificate verification **only in controlled environments**. |

## Understanding results

| Classification | Meaning |
|---|---|
| `EOL_UNSUPPORTED` | The identified PHP branch is unsupported upstream (PHP 8.1 or older in the initial support model). Upgrade planning is required. **This does not confirm exposure to either CVE.** |
| `PENDING_VENDOR_MATRIX` | A PHP 8.2–8.5 installation was observed, but no verified fix threshold is configured for its branch. **Not an RCE finding.** |
| `NO_VERSION_OBSERVED` | HTTP headers did not disclose a PHP version. **This does not prove the absence of PHP.** |
| `BELOW_OFFICIAL_FIX` | The observed upstream version falls below a vendor-verified threshold configured in `advisory.json`. Check vendor backports and any exploitation prerequisites. |
| `MEETS_UPSTREAM_VERSION` | The version meets or exceeds the configured upstream threshold. Verify the actual running service, installed packages, and patch deployment. **Not a guarantee of security.** |
| `PRERELEASE_REVIEW` | A release candidate, alpha, or beta build needs an explicit vendor determination. |
| `BRANCH_NOT_ASSESSED` | The identified version does not match a supported branch in the tool's initial support model. |
| `PROBE_ERROR` / `INPUT_ERROR` | The check could not be completed or the input was invalid. |

### Important interpretation boundaries

- HTTP version headers can be absent, inaccurate, or inserted by intermediary devices.
- Detecting WordPress, Drupal, Joomla, Laravel, or another PHP-based product does **not** establish the actual PHP runtime version.
- Local CLI results do **not** establish the PHP version used by a web server or container.
- Distribution-specific security patches may be **backported** without changing the upstream version number.
- A version comparison alone cannot demonstrate remote reachability, configuration-dependent preconditions, or RCE exploitability.
- For production decisions, prefer authenticated package inventories, PHP-FPM/runtime inspection, operating-system security bulletins, and vendor advisories.

## Updating patch thresholds after the official release

1. Check the **official PHP security releases** for each maintained branch, including affected versions, fixed versions, and any applicable preconditions.
2. Edit `advisory.json`: set `release_status` to `"published"` and populate `minimum_fixed_versions` **only with verified upstream versions**. Each value must be a complete numeric PHP version such as `8.4.X` with `X` replaced by the actual official patch number.
3. Set `vendor_fix_reference` to the official HTTPS advisory or release URL.
4. Reassess authorized services or trusted inventory files; verify the runtime version and restart requirements after applying patches.
5. For vendor-backported fixes, document the package-specific evidence in `distro_package` and `notes`. **The tool does not automatically mark backported packages as fixed.**

Example configuration structure (illustrative placeholders; **do not paste as a working advisory**):

```json
{
  "release_status": "published",
  "minimum_fixed_versions": {
    "8.4": "8.4.X"
  },
  "vendor_fix_reference": "https://www.php.net/"
}
```

The example above is **not a valid fixed-version entry**. Use real, verified version numbers and keep all required fields from the existing `advisory.json`.

## Safety and operational scope

- Run the tool only against systems you own or have **explicit authorization** to assess.
- HTTP checks use `HEAD` and, if needed, `GET`; no authentication attempts, payload delivery, request bodies, or response-body parsing are performed.
- Each batch is limited to 2,000 URLs; request timeout and inter-request delay are configurable.
- HTTP redirects are followed **only when the hostname remains the same**.
- TLS certificates are validated by default. Use `--insecure` only when this is an approved testing exception.
- Client inventories and reports should **never be committed to Git**. The `reports/` directory is covered by `.gitignore`; use equivalent controls for real inventory files in other directories.
- Store, transmit, and disclose assessment reports under your organization's confidentiality policies.

## Official references

- [PHP security announcement — October 20, 2026](https://www.php.net/archive/2026.php#2026-10-20-1)
- [PHP supported versions](https://www.php.net/supported-versions.php)
- [PHP end-of-life versions](https://www.php.net/eol.php)
- [CERT-EU Security Advisory 2026-018](https://www.cert.europa.eu/publications/security-advisories/2026-018/)


## License

MIT License · Copyright © 2026 Grupo Oruss. Use responsibly and with authorization.
