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
```bash
sudo nmap -sC -sV -T4 -p- -oN nmap/beskarNights.nmap 10.10.130.11
```
![nmap](https://github.com/rootshooter/rootshooter.github.io/blob/main/_posts/img/beskar/nmap_1.png)
