# Lab Report - BruteIt


# Overview 
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/bruteit
- **Tags**: #enumeration #Brute-force #privesc 

## Challenge Description 
>**Learn how to brute, hash cracking and escalate privileges in this box!**

## Resolution Summary 
**We performed an `Nmap` scan to discover available services, we found an HTTP server running on port 80. We fuzzed the website's directories with `GoBuster` in order to find the hidden directories, which lead us to a login portal. We found the username hidden in plaintext in the Source Page. Hence, we performed a Brute-force attack and we recovered a pair of valid credentials. Upon login, we found a username and an RSA private key, which we cracked (for its passphrase) using `JTR`. Finally, we exploited misconfigured sudo privileges on the `cat` command in order to gain root access (we recovered root's password and cracked it using `JTR` again).** 
# Information Gathering 
- **Since we had an IP address as a starting point, we began by performing an `Nmap` scan on the target in order to find online services and their versions (for version-related vulnerabilities):**
```bash
sudo nmap -sV 10.10.30.216
```
	- Note: the `-p-` flag did not reveal additional results.

- **We found an SSH (22) server and an HTTP (80) server. We started by investigating the web server, hoping to find an entry point to exploit.** 

## HTTP (80)
- **We were welcomed with the Apache2 Ubuntu default page.**

- **To begin with, we started by launching `Gobuster` in order to find hidden directories and further enumerate the web page:**
```bash
gobuster dir -u 10.10.30.216 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```

- **Right away, we found an interesting directory `/admin`, which led us to a login page. From there, we attempted to find a valid pair of credentials to access the directory's content.** 
# Exploitation 
## HTTP (80)
- **Since we came across a login page, we attempted to see how the login request was built. For that purpose, we used `Burp Suite`: we intercepted a login request and sent it to `Repeater` for further investigation.** 

- **First, we attempted to see if we could enumerate the usernames by trying common ones and see if there is any specific error message triggered or if the response's body is different in size compared to requests with dummy values.**

- **However, it was specified (in commentary, plaintext, also visible from Source Page) that the username was `admin`.**

- **From there, we directly attempted to brute force the password by using `ffuf`, we filtered the responses by HTTP response code :**
```bash
ffuf -w /home/kali/Downloads/rockyou.txt:FUZZ -X POST -d "user=admin&pass=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.30.216/admin/ -fc 200
```

- **Hence, we found the following pair of credentials:** 
	- **`admin:xavier`**.

- **From, there, we were able to retrieve an RSA private key, which we saved into a file and changed permissions to fit those of a private key:**
```bash
nano key #Then we pasted the private key into the file
chmod 600 key #Gives private file persmissions to key (required for RSA private keys)
```

- **Finally, we attempted to log into the SSH server we found earlier as john (owner of the private key) with the key recovered:**
```bash
ssh -i key john@10.10.30.216
```

- **However, we were tasked for a passphrase, and giving a blank one did not work. Hence, we tried to crack the RSA key with JTR.** 

- **First, we need to convert the key into John-readable hash format, we used the following to do so:** 
```bash
python3 /usr/share/john/ssh2john.py key > key.hash
```

- **Then we cracked the passphrase with:**
```bash
john --wordlist=/home/kali/Downloads/rockyou.txt key.hash
```
- **And we found the following passphrase:**
	- **`rockinroll`**.

- **Now we attempted to log into the SSH server again, and we succeeded:**
```bash
ssh -i key john@10.10.30.216
```

- **And we were greeted with a first flag:**
	- user.txt:**`THM{a_password_is_not_a_barrier}`**.

- **Next, we attempted to elevate our privileges and gain root access over the system.** 
# Privilege Escalation 
- **When testing for common privesc path, we found a low-hanging fruit : we were allowed to run cat as root with sudo:** 
```bash
sudo -l 
User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

- **This allowed to immediately access the root flag:** 
```bash 
sudo cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```

- **Bonus: since we were also tasked to find the root's user password, we attempted the following:**
```bash
sudo cat /etc/shadow | grep root
#Results
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
```

- **We tried to crack the hash by using JTR again and found the password:**
```bash
john --wordlist=/home/kali/Downloads/rockyou.txt hash.txt
#Result 
football 
```
# Trophy 
**User.txt → `THM{a_password_is_not_a_barrier}`**  

**Root.txt → `THM{pr1v1l3g3_3sc4l4t10n}`**

# Remediation Summary
- **Dangerous Sudo Permissions**: Avoid allowing users to run sudo on sensitive binaries like cat, base64,head,... 
- **Code Sanitization**:  Avoid leaving commentaries in your code (Source Page here) that may reveal sensitive information. 
- **Stronger Passwords**: Use stronger passwords to not be easily vulnerable to Brute-force attacks. 

# Lessons Learned
- **RSA Key Permission**: an RSA key needs to have permission `600` set. 
- **RSA key Cracking**: use ``ssh2john`` in order to convert a private key into john-readable hash format before cracking it. Useful when looking for the passphrase.
