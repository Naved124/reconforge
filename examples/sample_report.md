# Reconnaissance Report

- **Generated:** 2026-10-30 07:45 UTC
- **Authorized scope:** 10.10.11.0/24
- **Hosts up:** 1
- **Candidate CVEs:** High 1, Medium 1

> CVE matches are based on service banners and keyword search. Treat them as leads
> to verify manually, not as confirmed vulnerabilities.

## 10.10.11.23 (target.htb)

OS guess: Linux 4.15 - 5.8

| Port | Service | Version | CVEs | Metasploit |
|---|---|---|---|---|
| 22/tcp | ssh | OpenSSH 7.2p2 | 2 | 1 |
| 80/tcp | http | Apache httpd 2.4.18 | 0 | 0 |
| 443/tcp | http | nginx | 0 | 0 |

### 22/tcp - OpenSSH 7.2p2

- **CVE-2016-10009** (HIGH, CVSS 7.3): Untrusted search path vulnerability in ssh-agent in OpenSSH before 7.4.
- **CVE-2016-6210** (MEDIUM, CVSS 5.9): sshd in OpenSSH before 7.3 allows remote attackers to enumerate users via timing.
  - Metasploit auxiliary: `auxiliary/scanner/ssh/ssh_enumusers`

### 80/tcp - Apache httpd 2.4.18

**Manual web testing:** proxy `http://10.10.11.23:80/` through Burp Suite; check auth, input handling, hidden directories and known CMS paths.

### 443/tcp - nginx

**Manual web testing:** proxy `https://10.10.11.23:443/` through Burp Suite; check auth, input handling, hidden directories and known CMS paths.

## Next steps

1. Verify each candidate CVE against the exact version (banner, changelog, behaviour).
2. Review `msf_suggestions.rc`; every line is commented out until you confirm it.
3. Test flagged web services manually in Burp Suite.
4. Record confirmed findings with evidence before any exploitation attempt.
