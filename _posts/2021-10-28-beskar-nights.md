## Beskar Nights - Official Walkthrough

### Introduction
Beskar Nights is a vulnerable Linux machine with an interesting twist. This machine will test your 
exploit development knowledge and keep you on your toes from start to finish. The foothold comes 
through the exploitation of a custom binary that is running on the production system. Once a low-level shell has been established, some quick enumeration of the system leads to privilege 
escalation; resulting in a root shell! With the introduction out of the way, let's jump right in!

### Scanning & Enumeration 
A crucial part of penetration testing is the Information Gathering phase. In this part of the process 
the tester collects information on the target through active and passive reconnaissance. In this 
case, we will be actively collecting information on the target in the form of a port scan. We will use 
Nmap to collect open TCP ports, Service Versions, and run scripts against the services detected. To 
start things off, we will scan the target IP address using the following command:
```console
sudo nmap -sC -sV -T4 -p- -oN nmap/beskarNights.nmap 10.10.130.11
```
<a href="/images/nmap_1.png"><img src="/images/nmap_1.png"></a>

There is a lot of valuable information that can be collected from the output of this Nmap scan. First, 
we can see that the system has TCP ports 80, 2222, and 31337 open and accessible by the public. 

We can also see that the system is potentially running Ubuntu Linux based on the output of the SSH service version information. Nmap has a hard time identifying the service that is running on port 31337. Since this is interesting, that is where we will start.

In order to investigate the interesting service further, we will use Netcat to make a connection and interact with it. To perform this investigation, we will use the following command:
```console
nc -nv 10.10.130.11 31337
```
<a href="/images/nc_1.png"><img src="/images/nc_1.png"></a>

As you can see in the screenshot above, if we enter HELP, the service simply echoes back the user input. Although this is interesting, not knowing what the service is makes it difficult to find vulnerabilities to exploit. In this case, we will move onto the HTTP service running on port 80.

To get an idea what is running on the HTTP service, we will browse to http://10.10.130.11/. Before the page is loaded, a HTTP Basic Authentication window is displayed. The message in the login window says “Restricted Content”.

<a href="/images/basic.png"><img src="/images/basic.png"></a>

This is an interesting finding. It is a good possibility that this site is still under development and the creator implemented an authentication mechanism to keep the contents private. We’ll try some simple username/password combinations to test the password practices of the target. The first and most popular combination we will use is **admin:admin**. 

<a href="/images/auth.png"><img src="/images/auth.png"></a>

It appears that the target is not using strong password practices because the credentials work and we are authenticated to the page!

<a href="/images/index.png"><img src="/images/index.png"></a>

One of the first things we will check is for the presence of a robots.txt file. This is accomplished by browsing to http://10.10.130.11/robots.txt. 

<a href="/images/robots.png"><img src="/images/robots.png"></a>

There is one entry in the Disallow section: /dev. This is an interesting finding so that is where we will look next.

Browsing to http://10.10.130.11/dev/ brings up a directory listing that contains an interesting executable file. It is obvious at this point that the site is still under development and there aren’t many security-focused practices being implemented. This binary seems to be interesting so we will download it to our local system.

<a href="/images/beskarexe.png"><img src="/images/beskarexe.png"></a>

To download the file, we will simply click on the executable and a prompt window will appear asking us what we want to do with the file. In this case, we will select the save option in order to download it to the local system.

<a href="/images/download.png"><img src="/images/download.png"></a>

Now that we have a copy on our local system, we can inspect its behavior in more detail by transferring it to a Windows system.

### Exploit Development
The first thing we will do is run the program to check the behavior. Normally, running a random executable file found online would be a bad practice. Since this is being run in a virtual environment that is contained to a local network, it is safe to do. The reason it is a bad practice is you could potentially introduce malware into your system or network if you are not careful. Use common sense when dealing with executables found online!

#### Fuzzing
Once we have the executable transferred to our Windows system, we will run it to check out what it does.
