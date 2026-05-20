# NmapLens Report

## Scan Summary

- Scanner: nmap 7.95
- Scan start: 2026-05-20 12:00 UTC
- Total hosts: 2
- Online hosts: 2
- Total open ports: 6
- Low risk hosts: 0
- Medium risk hosts: 1
- High risk hosts: 1
- Critical risk hosts: 0

## Host List

- 192.168.1.10 (Medium, score 35)
- 192.168.1.20 (High, score 65)

## Risk Table

| Host | Status | Risk Score | Risk Level | Open Ports |
| --- | --- | ---: | --- | ---: |
| 192.168.1.10 | up | 35 | Medium | 3 |
| 192.168.1.20 | up | 65 | High | 3 |

## Detailed Host Findings

### 192.168.1.10

- Hostname: gateway.local
- MAC address: 00:11:22:33:44:55
- Vendor: Intel
- OS guess: Linux 6.x
- Risk score: 35
- Risk level: Medium

#### Risk Reasons

- SSH should be restricted to trusted administrative networks.
- HTTP traffic is not encrypted.
- SMB exposure can increase lateral movement risk.

#### Open Ports

- `22/tcp` ssh (OpenSSH 9.6 protocol 2.0)
  - CPE: cpe:/a:openbsd:openssh:9.6
- `80/tcp` http (nginx 1.24.0)
  - CPE: cpe:/a:nginx:nginx:1.24.0
- `445/tcp` microsoft-ds (Samba smbd 4.18.0)

#### Recommended Next Commands

- `nmap --script ssh2-enum-algos -p22 192.168.1.10`
- `nmap --script http-title,http-headers,http-methods -p80 192.168.1.10`
- `nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p445 192.168.1.10`

### 192.168.1.20

- Hostname: N/A
- MAC address: N/A
- Vendor: N/A
- OS guess: Microsoft Windows 10 or 11
- Risk score: 65
- Risk level: High

#### Risk Reasons

- FTP may expose credentials if not protected.
- Telnet is exposed and uses clear-text communication.
- RDP should be protected with VPN, MFA, and strict access control.

#### Open Ports

- `21/tcp` ftp (vsftpd 3.0.5)
- `23/tcp` telnet (BusyBox telnetd)
- `3389/tcp` ms-wbt-server (Microsoft Terminal Services)

#### Recommended Next Commands

- `nmap --script ftp-anon,ftp-syst -p21 192.168.1.20`
- `nmap -sV -p23 192.168.1.20`
- `nmap --script rdp-enum-encryption -p3389 192.168.1.20`

## Disclaimer

This tool is intended for educational and authorized security testing only. Only scan systems you own or have explicit permission to test.
