# Reconnaissance Report

- **Generated:** 2026-10-30 09:57 UTC
- **Authorized scope:** 10.129.64.80/32
- **Hosts up:** 1
- **Misconfigurations:** High 1, Low 1
- **Candidate CVEs:** High 1

> Misconfigurations come from Nmap script output. CVE matches are based on service
> banners and keyword search. Treat both as leads to verify manually.

## 10.129.64.80

**Priority findings:**

- **[HIGH] Anonymous FTP login allowed** (`ftp-anon`): Anonymous FTP login allowed (FTP code 230) / -rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
- **[LOW] FTP sends credentials in cleartext** (`service`): ftp on 21/tcp is not wrapped in TLS

| Port | Service | Version | Issues | CVEs | Metasploit |
|---|---|---|---|---|---|
| 21/tcp | ftp | vsftpd 3.0.3 | 2 | 1 | 0 |

### 21/tcp - vsftpd 3.0.3

- 2 misconfiguration(s) listed under Priority findings
- *ftp-syst*: STAT: / FTP server status: / Connected to ::ffff:10.10.16.123
- **CVE-2021-30047** (HIGH, CVSS 7.5): VSFTPD 3.0.3 allows attackers to cause a denial of service due to limited number of connections allowed.

## Next steps

1. Confirm each priority finding by hand (for example, log in to an anonymous FTP service).
2. Verify each candidate CVE against the exact version (banner, changelog, behaviour).
3. Review `msf_suggestions.rc`; every line is commented out until you confirm it.
4. Test flagged web services manually in Burp Suite.
5. Record confirmed findings with evidence before any exploitation attempt.
