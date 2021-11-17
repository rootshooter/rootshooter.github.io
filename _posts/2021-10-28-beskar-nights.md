## Beskar Nights - Official Walkthrough

### Introduction
Beskar Nights is a vulnerable Linux machine with an interesting twist. This machine will test your 
exploit development knowledge and keep you on your toes from start to finish. The foothold comes 
through the exploitation of a custom binary that is running on the production system. Once a lowlevel shell has been established, some quick enumeration of the system leads to privilege 
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
BESKAR NIGHTS 
We can also see that the system is potentially running Ubuntu Linux based on the output of the SSH 
service version information. Nmap has a hard time identifying the service that is running on port 
31337. Since this is interesting, that is where we will start.
In order to investigate the interesting service further, we will use Netcat to make a connection and 
interact with it. To perform this investigation, we will use the following command:
```console
nc -nv 10.10.130.11 31337
```
As you can see in the screenshot above, if we enter HELP, the service simply echoes back the user input. Although this is interesting, not knowing what the service is makes it difficult to find vulnerabilities to exploit. In this case, we will move onto the HTTP service running on port 80.

To get an idea what is running on the HTTP service, we will browse to http://10.10.130.11/. Before the page is loaded, a HTTP Basic Authentication window is displayed. The message in the login window says “Restricted Content”.
