# reconforge

Scoped recon-to-report automation for **authorized** penetration tests.

reconforge takes a target from an approved scope list, runs an Nmap service scan,
looks up known CVEs for each detected service version in the NVD database, maps
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
- **CVE lookup** - queries the NVD CVE API 2.0 by product and version, sorts results by
  CVSS severity, and caches responses so repeat runs don't hit rate limits.
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
`--nmap-args "-sV -p-"`, `--msf-db PATH`. Set `NVD_API_KEY` for faster CVE lookups.

Each run writes `reports/<timestamp>/report.md`, `msf_suggestions.rc` and, for scans, `nmap.xml`.
See `examples/` for sample output (generated from test fixture data).

## Design notes

- CVE matching uses banner product + version keyword search, so results are **leads to
  verify**, not confirmed vulnerabilities; the report says so explicitly.
- Services without a detected version are not queried, since product-only searches
  return thousands of irrelevant CVEs.
- NVD requests are spaced to respect the public rate limit (about 5 per 30 seconds without a key).

## Tests

```bash
pytest -q
```

## Legal

Only use reconforge against systems you own or have explicit written permission to
test (for example Hack The Box / TryHackMe lab machines while connected to their VPN).

## License

MIT
