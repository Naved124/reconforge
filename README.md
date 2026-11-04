# reconforge

Scoped recon-to-report automation for **authorized** penetration tests.

reconforge takes a target from an approved scope list, runs an Nmap service scan,
matches each detected service version to known CVEs in the NVD database (by CPE), maps
those CVEs to Metasploit modules, flags web services for manual Burp Suite testing,
and writes a Markdown report a tester can work from.

It automates the repetitive first hour of an engagement while keeping the human in
control: nothing is exploited automatically.

## Features

- **Scope guard** - every target must be listed (IP or CIDR) in a scope file. Out-of-scope
  targets are refused *before* Nmap runs, and hosts found in an imported scan are checked too.
- **Nmap integration** - runs `nmap -sV -sC` (or your own args) or parses an existing `-oX` file.
- **Misconfiguration findings** - reads Nmap script output and flags real entry points that
  are not CVEs (anonymous FTP, SMB guest access or signing not required, empty database
  passwords, exposed `.git`, risky HTTP methods, cleartext protocols) as priority findings.
- **CPE-based CVE matching** - uses the CPE Nmap reports, queries the NVD CVE API 2.0, checks
  the detected version against each CVE's affected ranges locally, and labels every CVE with a
  confidence level (see [CVE matching](#cve-matching)). Responses are cached on disk.
- **Metasploit mapping** - reads Metasploit's own `modules_metadata_base.json` to find
  exploit/auxiliary modules referencing each CVE, and writes a resource script in which
  **every line is commented out** until reviewed.
- **Web flags** - HTTP/HTTPS services get a ready Burp Suite target URL in the report.
- **Markdown report** - per-host tables, CVEs by severity, module suggestions, next steps.
- No third-party dependencies (Python standard library only).

## Install

```bash
git clone https://github.com/<you>/reconforge && cd reconforge
pip install -e .            # or: pip install -e ".[dev]" to run tests
```

Requires Python 3.10+, `nmap` in PATH for `scan`, and optionally Metasploit installed
for module suggestions (Kali/Parrot ship it).

## Usage

```bash
# 1. list what you are authorized to test
echo "10.10.11.0/24   # HTB lab" > scope.txt

# 2. scan and report
reconforge scan --scope scope.txt --target 10.10.11.23

# or analyse a scan you already ran
reconforge report --scope scope.txt --xml nmap_output.xml
```

Options: `--out DIR` (default `reports`), `--offline` (skip CVE lookups),
`--nmap-args "-sV -p-"`, `--msf-db PATH`, `--cache-dir DIR` (default `~/.cache/reconforge/nvd`),
`--cache-ttl HOURS` (default 24). Set `NVD_API_KEY` for a higher NVD rate limit.

Each run writes `reports/<timestamp>/report.md`, `msf_suggestions.rc` and, for scans, `nmap.xml`.
See [Examples](#examples) for sample output.

## CVE matching

1. **CPE from Nmap.** Each service's `<cpe>` elements (CPE 2.2, e.g. `cpe:/a:vsftpd:vsftpd:3.0.3`)
   are converted to CPE 2.3 (`cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*`). Only application
   CPEs (`a`) are used; OS and hardware CPEs would match thousands of unrelated CVEs.
2. **NVD query by product.** The NVD API 2.0 is queried with `virtualMatchString=cpe:2.3:a:<vendor>:<product>`
   (after the vendor handling described [below](#vendor-names)), which returns every CVE whose
   configurations cover *any* version of that product, including version ranges. If the CPE has no version, the numeric version from the Nmap banner is used;
   if there is no version at all the service is not queried.
3. **Local version check.** For each CVE, reconforge walks `configurations` -> `nodes` -> `cpeMatch`
   and applies `versionStartIncluding/Excluding` and `versionEndIncluding/Excluding`. Only
   `vulnerable: true` entries count, negated nodes are ignored, and NVD's split of
   `7.2p2` into version `7.2` + update `p2` is handled. CVEs whose ranges do not contain the
   detected version are dropped.
4. **Version comparison** handles dotted numbers (`2.4.41`), patch suffixes (`7.4p1` sorts after `7.4`)
   and pre-releases (`2.0rc1` before `2.0`). Anything it cannot compare reliably (for example
   `2.4.41-4ubuntu3`) is never silently dropped or asserted; it becomes `unconfirmed`.

### Confidence levels

| Level | Meaning |
|---|---|
| `confirmed-range` | The detected version falls inside an affected range listed by NVD. |
| `exact-cpe` | The detected version equals a vulnerable CPE listed by NVD. |
| `unconfirmed` | No usable version, an uncomparable version, or a reason to trust the match less (below). |
| `keyword-guess` | Fallback only: the service had no CPE, so NVD was searched by banner keywords. |

A match is capped at `unconfirmed`, with the reason shown in the report, when:

- **Vendor alias** - Nmap and NVD name the vendor differently and neither the alias table nor an NVD
  deprecation mapping (see below) explains it. If NVD has nothing under Nmap's vendor, the query is
  repeated with a wildcard vendor, and the reason reads `vendor alias` (or
  `vendor alias (ambiguous: ...)` when NVD knows several vendors for that product name).
- **Distro package** - the banner carries an Ubuntu/Debian/el7-style marker, so fixes may be
  backported without changing the upstream version number.
- **Platform-dependent** - the CVE only applies when running on a specific platform.
- **MariaDB posing as MySQL** - MariaDB often answers the MySQL probe with a banner such as
  `5.5.5-10.3.23-MariaDB`, whose numbers mean nothing for Oracle MySQL. Such results are never
  `exact-cpe` or `confirmed-range` against MySQL; the reason mentions MariaDB.

Within a service, CVEs are listed by confidence first, then severity.

### Vendor names

Nmap's CPE vendors sometimes differ from NVD's current ones. reconforge resolves this from NVD data, in order:

1. **Alias table** (`reconforge/vendors.py`). A short static table built by comparing Nmap's CPEs
   (`nmap-service-probes`) with the NVD CPE dictionary. An entry exists only where the vendors differ
   *and* NVD has exactly one vendor for the product. Currently: `vsftpd` -> `vsftpd_project`.
   Matches keep full confidence; the reason reads `vendor via alias table: vsftpd → vsftpd_project`.
2. **NVD deprecation.** If at least 90% of the Nmap vendor's CPEs for the product are deprecated in the
   NVD CPE dictionary, the `deprecatedBy` field is followed (up to 6 hops, cycles rejected) to live CPEs.
   If every deprecated CPE ends at exactly one live vendor of the same product, both the original and the
   replacement vendor are queried, CVEs are deduplicated by ID keeping the strongest confidence, and
   matches through the replacement count as real vendor matches (they can reach `exact-cpe` and
   `confirmed-range`). The reason reads `vendor via NVD deprecation: igor_sysoev → f5`. Examples from
   NVD data: `igor_sysoev:nginx` -> `nginx:nginx` -> `f5:nginx`, and `mysql:mysql` -> `oracle:mysql`.
   The resolved mapping is cached with the same TTL as CVE responses (one CPE API request per product).
3. **Wildcard fallback** (capped at `unconfirmed`, as above) only when neither applies and NVD has nothing under the vendor.

The distro-package downgrade applies after any of these.

### Caching and rate limits

NVD responses (and resolved vendor mappings) are cached per query under `~/.cache/reconforge/nvd/` (or `$XDG_CACHE_HOME`, or
`--cache-dir`) and reused for 24 hours (`--cache-ttl`). Requests follow NVD's limits: 5 per
30 seconds without an API key, 50 with `NVD_API_KEY`; throttled responses (403/429/503) are retried
with backoff.

### Limits

Matching is only as good as the NVD data and the banner. NVD can lag behind new CVEs, a banner can be
wrong or hidden, and `exact-cpe`/`confirmed-range` still mean "listed as affected", not "exploitable".
Always verify before acting.

## Examples

- `examples/htb_fawn_report.md` - real v0.2 output (keyword matching) for HTB Fawn.
- `examples/htb_fawn_report_v0.3.md` - v0.3 output for the same service, generated from
  `examples/htb_fawn_scan.xml`, which is reconstructed from the v0.2 report (the original XML was not saved).
- `examples/sample_report.md` - generated from the test fixtures with stubbed NVD responses.

## Tests

```bash
pytest -q
```

## Legal

Only use reconforge against systems you own or have explicit written permission to
test (for example Hack The Box / TryHackMe lab machines while connected to their VPN).

## License

MIT
