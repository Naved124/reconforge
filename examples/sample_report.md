# Reconnaissance Report

- **Generated:** 2026-11-04 14:52 UTC
- **Authorized scope:** 10.10.11.0/24
- **Hosts up:** 1
- **Misconfigurations:** High 1, Medium 1, Low 1
- **Candidate CVEs:** Critical 1, High 2, Medium 2
- **CVE confidence:** unconfirmed 5

> Misconfigurations come from Nmap script output. CVEs are matched on the CPE Nmap
> reports, with the detected version checked against NVD's affected ranges. Confidence:
> `confirmed-range` (version inside an affected range), `exact-cpe` (exact CPE match),
> `unconfirmed` (no usable or comparable version, or limited trust such as a distro
> package or vendor alias) and `keyword-guess` (banner keyword search, no CPE).
> Treat all of them as leads to verify manually.

## 10.10.11.23 (target.htb)

OS guess: Linux 4.15 - 5.8

**Priority findings:**

- **[HIGH] Anonymous FTP login allowed** (`ftp-anon`): Anonymous FTP login allowed (FTP code 230) / -rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
- **[MEDIUM] SMB message signing not required** (`smb2-security-mode`): 3:1:1: / Message signing enabled but not required
- **[LOW] FTP sends credentials in cleartext** (`service`): ftp on 21/tcp is not wrapped in TLS

| Port | Service | Version | Issues | CVEs | Metasploit |
|---|---|---|---|---|---|
| 21/tcp | ftp | vsftpd 3.0.3 | 2 | 0 | 0 |
| 22/tcp | ssh | OpenSSH 7.2p2 | 0 | 5 | 2 |
| 80/tcp | http | Apache httpd 2.4.18 | 0 | 0 | 0 |
| 443/tcp | http | nginx | 0 | 0 | 0 |

### 21/tcp - vsftpd 3.0.3

- 2 misconfiguration(s) listed under Priority findings
- *ftp-syst*: STAT: / FTP server status: / vsFTPd 3.0.3 - secure, fast, stable

### 22/tcp - OpenSSH 7.2p2

- **CVE-2023-38408** `[unconfirmed]` (CRITICAL, CVSS 9.8): The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-con... *(distro package, fixes may be backported; 7.2p2 within affected range < 9.3)*
- **CVE-2016-6515** `[unconfirmed]` (HIGH, CVSS 7.5): The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a deni... *(distro package, fixes may be backported; 7.2p2 within affected range <= 7.2)*
- **CVE-2016-10009** `[unconfirmed]` (HIGH, CVSS 7.3): Untrusted search path vulnerability in ssh-agent.c in ssh-agent in OpenSSH before 7.4 allows remote attackers to execute arbitrary local PKCS#11 modules by leveraging control over ... *(distro package, fixes may be backported; 7.2p2 within affected range <= 7.3)*
- **CVE-2016-6210** `[unconfirmed]` (MEDIUM, CVSS 5.9): sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remo... *(distro package, fixes may be backported; 7.2p2 within affected range <= 7.2)*
  - Metasploit auxiliary: `auxiliary/scanner/ssh/ssh_enumusers`
- **CVE-2018-15473** `[unconfirmed]` (MEDIUM, CVSS 5.3): OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has be... *(distro package, fixes may be backported; 7.2p2 within affected range <= 7.7)*
  - Metasploit auxiliary: `auxiliary/scanner/ssh/ssh_enumusers`

### 80/tcp - Apache httpd 2.4.18

**Manual web testing:** proxy `http://10.10.11.23:80/` through Burp Suite; check auth, input handling, hidden directories and known CMS paths.

### 443/tcp - nginx

**Manual web testing:** proxy `https://10.10.11.23:443/` through Burp Suite; check auth, input handling, hidden directories and known CMS paths.

## Next steps

1. Confirm each priority finding by hand (for example, log in to an anonymous FTP service).
2. Verify each candidate CVE against the exact version (banner, changelog, behaviour).
3. Review `msf_suggestions.rc`; every line is commented out until you confirm it.
4. Test flagged web services manually in Burp Suite.
5. Record confirmed findings with evidence before any exploitation attempt.
