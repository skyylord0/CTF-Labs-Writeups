# Lab Report - Lookup


# Overview 
---
- **Category**: Web
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/lookup

## Challenge Description 
---
> **A beginner boot-to-root machine. 

## Resolution Summary 
---
**We discovered available services with an `Nmap` scan, revealing an SSH server and an HTTP web application. We identified a login page and exploited a difference in server responses to enumerate valid usernames with `ffuf`, then brute-forced the password for user `jose`. Upon logging in, we were redirected to a subdomain running `elFinder`, which was vulnerable to a command injection exploit (`CVE-2019-9194`), giving us an initial foothold via `Metasploit`. For privilege escalation, we abused a SUID binary (`pwm`) that relied on the `id` command by hijacking the `PATH` variable with a fake `id` script, recovering a password list that we sprayed against SSH with `Hydra` to log in as `think`. Finally, we leveraged a `sudo` misconfiguration on `/usr/bin/look` to read the root flag directly.**

# Information Gathering 
---
## Active Reconnaissance
---
- **As we were given an IP address, we started by performing an Nmap scan in order to discover running services on the target.**
- **We used the `-sV` flag to uncover the services' versions, which could allow us to discover version-related vulnerabilities.** 
```bash
nmap -sV 10.10.40.250
```
	- Note: adding the -p- flag did not lead to more results.

- **We discovered two running services : an SSH server (22) and an HTTP server (80) :** 
```bash 
#Results
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

- **Hence we started by investigating the web application on port 80.**

### HTTP server (80)
---
- **When accessing the website, we were greeted by a login page, which could be tested for injections attacks.** 

- **We started by looking at the Source Page, we found that the form action value is `login.php`, which indicates to us the directory (`/login.php`) we need to target when fuzzing.**
- **Next, we began looking for hidden directories by using GoBuster with a medium-list directories from SecList.**  
```bash
gobuster dir -u 10.10.40.250 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

- **We did not get any results from Gobuster.**

- **We attempted to look for subdomains using Sublist3r :**
```bash
sublist3r -d lookup.thm
```

- **We did not get any results either, then we focused on the login form.**
# Exploitation 
---
### HTTP server (80)
---
- **As we have found a login page, we tried and see how the requests behave by using Burp Suite.** 
- **After sending the request to Repeater, we find that if you provide the correct username, the `Content-length` value changes (74 for invalid username and password, 62 for invalid password only).**

	- **Note**: Before fuzzing, we tried SQL injections attacks, but all the attempts were unsuccessful.

- **We tested some common credentials and admin was a valid one.**

- **We previously found that the form action page is /login.php, which we will use to fuzz credentials using `ffuf`.**
```bash
ffuf -u http://lookup.thm/login.php -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -X POST -d "username=FUZZ&password=dummy" -H "Content-Type: application/x-www-form-urlencoded" -fs 74 
```

- **We found that `jose` was a valid username too.** 

- **Now let's find the password, we will continue to use `ffuf`:** 
```bash
ffuf -u http://lookup.thm/login.php -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-dup.txt:FUZZ -d "username=jose&password=FUZZ" -X POST -H "Content-Type: application/x-www-form-urlencoded" -fs 62
```

- **We found that `pasword123` is the password of `jose`, we will now try to log in the web page and see what happens, we will also save those credentials to spray them later if needed (there is an SSH server available too).**

- **When using the credentials `jose:password123` to log in, we are redirected to `files.lookup.thm` where we find numerous text files that contain random words for the most of it. Except the `credentials.txt` file that contains `think:nopassword`.**
	- Note : we made a wordlist out of those words and used it to fuzz both the login page and the SSH server, but it was unsuccessful. 

- **Upon further investigation on the software used here (elFinder), we discover that it is vulnerable (CVE-2019-9194). Hence, we launched Metasploit and perform**
```metasploit
search elfinder

use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
```

- **We set the options :** 
```metasploit
set rhosts 10.10.40.250

set vhost files.lookup.thm
```

- **Then we `run` the exploit, we end up getting a meterpreter shell on the target.**
# Privilege Escalation 
---
- **Now we are looking to increase our privileges after gaining initial foothold on the target system.** 
- **First, we check if the Kernel version is vulnerable, we find that it is indeed. We use DirtyPipe exploit but it do not work.** 

- **Hence, we check for SUID files by using**
```bash
find / -perm -u=s -type f 2>/dev/null
```

- **We stumble upon a mysterious binary : `/usr/sbin/pwm`. It seems to look for a specific file `.password` in the current user home directory (uses id to identify the current user).**
- **After looking around a bit, we find the said file in `/home/think`.**

- **The goal now is to access that file, this is how we will proceed : we will create a malicious binary that mimics the `id` command but returns only the `think` user.**
```bash
echo '#!/bin/bash' > /tmp/id
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> /tmp/id
chmod +x /tmp/id
```

- **Then we edit the PATH variable so the binary picks up our fake `id` rather than the original one.** 
```bash
export PATH=/tmp:$PATH/
```

- **It was successful, we saved the passwords and used them to connect to the SSH server. We found the matching credentials : `think:josemario.AKA(think)` using Hydra:** 
```bash
hydra -l think -P /tmp/passwords.txt ssh://10.10.227.56
```

- **After logging in, we find the `user.txt` flag.** 

- **Now we attempt to elevate our priviliges by using `sudo -l` to display commands that we can use as a super user on our current account. We find that `/usr/bin/look` falls under this category.**
- **We use GTFOBins to find an exploit and we run it by using :** 
```bash
LFILE=/etc/shadow
sudo look '' "$LFILE"
```

- **However we can be tricky and (attempt to) access directly what we want :** 
```bash
LFILE=/root/root.txt
sudo look '' "$LFILE"
```
# Trophy 
---
**User.txt → `38375fb4dd8baa2b2039ac03d92b820e`** 

**Root.txt → `5a285a9f257e45c68bb6c9f9f57d18e8`**

# Extra Mile 
---
> **- A good habit would be to upgrade your shell whenever it is possible.** 
> **- We can try and crack the hashes in /etc/shadow.**
> **- We ended up not using the admin username on the web page (maybe it was only to discover the content-length change when the username already existed).**

# Remediation Summary
---
 - **Verbose error messages tend to give a lot of hints, they should be as generic as possible.** 
- **The /usr/bin/look binary is dangerous, it should not be available to run with sudo for any user.** 
# Lessons Learned
---
- **When using `ffuf`, it should target the form action (which you can find on the Source Page).** 
- **Always search if the software used is vulnerable (DB exploit).**  
- **When working with subdomains and Metasploit, you might need to change the vhost option (and set it to the vulnerable subdomain).** 
- **How we ended up bypassing the pwm binary by 'overwritting' an existing one (id) that it used : creating the malicious script and updating the PATH variable.**
- **Investigate any binary that looks suspicious (and has SUID bit set). And always have a look at GTFOBins when encountering one (note that if it is not there it does not mean that it cannot be exploited).** 