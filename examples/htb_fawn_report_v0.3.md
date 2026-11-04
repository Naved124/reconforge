# Reconnaissance Report

> **Example output (reconforge 0.3.0).** Generated from the reconstructed scan `examples/htb_fawn_scan.xml`, not from the original Nmap XML. Compare with `htb_fawn_report.md` (v0.2, real scan, keyword matching).

- **Generated:** 2026-11-04 14:52 UTC
- **Authorized scope:** 10.129.64.80/32
- **Hosts up:** 1
- **Misconfigurations:** High 1, Low 1
- **Candidate CVEs:** High 2
- **CVE confidence:** confirmed-range 1, exact-cpe 1

> Misconfigurations come from Nmap script output. CVEs are matched on the CPE Nmap
> reports, with the detected version checked against NVD's affected ranges. Confidence:
> `confirmed-range` (version inside an affected range), `exact-cpe` (exact CPE match),
> `unconfirmed` (no usable or comparable version, or limited trust such as a distro
> package or vendor alias) and `keyword-guess` (banner keyword search, no CPE).
> Treat all of them as leads to verify manually.

## 10.129.64.80

**Priority findings:**

- **[HIGH] Anonymous FTP login allowed** (`ftp-anon`): Anonymous FTP login allowed (FTP code 230) / -rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
- **[LOW] FTP sends credentials in cleartext** (`service`): ftp on 21/tcp is not wrapped in TLS

| Port | Service | Version | Issues | CVEs | Metasploit |
|---|---|---|---|---|---|
| 21/tcp | ftp | vsftpd 3.0.3 | 2 | 2 | 0 |

### 21/tcp - vsftpd 3.0.3

- 2 misconfiguration(s) listed under Priority findings
- *ftp-syst*: STAT: / FTP server status: / Connected to ::ffff:10.10.16.123
- **CVE-2021-3618** `[confirmed-range]` (HIGH, CVSS 7.4): ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing different protocols but using compatible certificates, such as multi-domain or... *(vendor via alias table: vsftpd → vsftpd_project; 3.0.3 within affected range < 3.0.4)*
- **CVE-2021-30047** `[exact-cpe]` (HIGH, CVSS 7.5): VSFTPD 3.0.3 allows attackers to cause a denial of service due to limited number of connections allowed. *(vendor via alias table: vsftpd → vsftpd_project; exact CPE version 3.0.3)*

## Next steps

1. Confirm each priority finding by hand (for example, log in to an anonymous FTP service).
2. Verify each candidate CVE against the exact version (banner, changelog, behaviour).
3. Review `msf_suggestions.rc`; every line is commented out until you confirm it.
4. Test flagged web services manually in Burp Suite.
5. Record confirmed findings with evidence before any exploitation attempt.
