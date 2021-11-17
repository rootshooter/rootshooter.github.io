## Beskar Nights - Official Walkthrough

### **Introduction**
Beskar Nights is a vulnerable Linux machine with an interesting twist. This machine will test your 
exploit development knowledge and keep you on your toes from start to finish. The foothold comes 
through the exploitation of a custom binary that is running on the production system. Once a low-level shell has been established, some quick enumeration of the system leads to privilege 
escalation; resulting in a root shell! With the introduction out of the way, let's jump right in!

### **Scanning & Enumeration** 
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

To get an idea what is running on the HTTP service, we will browse to **http://10.10.130.11/**. Before the page is loaded, a HTTP Basic Authentication window is displayed. The message in the login window says “Restricted Content”.

<a href="/images/basic.png"><img src="/images/basic.png"></a>

This is an interesting finding. It is a good possibility that this site is still under development and the creator implemented an authentication mechanism to keep the contents private. We’ll try some simple username/password combinations to test the password practices of the target. The first and most popular combination we will use is **admin:admin**. 

<a href="/images/auth.png"><img src="/images/auth.png"></a>

It appears that the target is not using strong password practices because the credentials work and we are authenticated to the page!

<a href="/images/index.png"><img src="/images/index.png"></a>

One of the first things we will check is for the presence of a robots.txt file. This is accomplished by browsing to **http://10.10.130.11/robots.txt**. 

<a href="/images/robots.png"><img src="/images/robots.png"></a>

There is one entry in the Disallow section: **/dev**. This is an interesting finding so that is where we will look next.

Browsing to **http://10.10.130.11/dev/** brings up a directory listing that contains an interesting executable file. It is obvious at this point that the site is still under development and there aren’t many security-focused practices being implemented. This binary seems to be interesting so we will download it to our local system.

<a href="/images/beskarexe.png"><img src="/images/beskarexe.png"></a>

To download the file, we will simply click on the executable and a prompt window will appear asking us what we want to do with the file. In this case, we will select the save option in order to download it to the local system.

<a href="/images/download.png"><img src="/images/download.png"></a>

Now that we have a copy on our local system, we can inspect its behavior in more detail by transferring it to a Windows system.

### **Exploit Development**
The first thing we will do is run the program to check the behavior. Normally, running a random executable file found online would be a bad practice. Since this is being run in a virtual environment that is contained to a local network, it is safe to do. The reason it is a bad practice is you could potentially introduce malware into your system or network if you are not careful. Use common sense when dealing with executables found online!

#### **Fuzzing**
Once we have the executable transferred to our Windows system, we will run it to check out what it does.

<a href="/images/run_1.png"><img src="/images/run_1.png"></a>

The program spawns a window and appears to be listening for incoming connections. Without decompiling the executable to see what port it is listening on; we can assume that it is listening on TCP port 31337. This is a valid assumption because of the weird service Nmap failed to identify earlier in the process. This can be checked by attempting to make a connection to the program on port 31337 from our Kali instance. We will use the following command to make the connection:
```console
nc -nv 192.168.110.129 31337
```
<a href="/images/nc_2.png"><img src="/images/nc_2.png"></a>

There are a few things to be noticed in the screenshot above. The first thing to notice is that the target IP address has changed. This is because we are using a local Windows system for testing the binaries functionality. The next thing to notice is that we get the exact output we received when interacting with the interesting service on the target. Now that we have control of the binary, and can make connections to it, we will develop a script to fuzz the input and test for a Buffer Overflow condition.

The script we will use to perform fuzzing can be seen in the screenshot below. It makes a TCP connection to the target IP address and port, sends “HELP” followed up with 100 “A’s”. This process will continue until a Socket Error is received. Each time it loops through, it will add 100 more “A’s” to the payload and send it to the target. If a Buffer Overflow condition is present, the buffer space will continue to fill until it is overrun with characters causing the program to crash. 

<a href="/images/fuzz_py.png"><img src="/images/fuzz_py.png"></a>

We will run the script against the target our local Windows system using the following command:
```console
python fuzz.py
```

<a href="/images/fuzzing.png"><img src="/images/fuzzing.png"></a>

After running the script, we get the program to crash at 300 bytes! This gives us a good indication that a Buffer Overflow condition could be present within the binary. We can inspect the traffic captured by Wireshark to see how out script interreacted with the binary. This will help guide us in the upcoming steps of the exploit development process.

<a href="/images/wireshark.png"><img src="/images/wireshark.png"></a>

There is a lot of valuable information that can be collected from the Wireshark capture shown in the screenshot above. We will focus on the packet sent that caused the program crash. Looking at the Packet Details pane (middle) we can see that 206 bytes were sent in this packet. This is interesting because our script rounded that number of to 300. This is because it is sending multiples of 100 at a time. This information is important because we know as long as we send more than 206 bytes, the program will crash. It also informs us that the EIP Offset will be at less than 206 bytes. The capture also shows in the Bytes Pane (bottom) the payload that was sent by the script. Now that we have this information, we can move onto finding the exact offset of the EIP.

#### **Finding the Offset**
For this part of the process, we will open and run the executable in Immunity Debugger on the Windows system. This is done by selecting **File --> Open --> beskarNights.exe --> Open**.

<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>

Once the program has been attached to Immunity Debugger, we can start the program execution two ways: the first is by selecting the Play icon in the top pane, or we can simply hit **F9** to start the program. This process will be used to attach and run the program for the rest of the process.

<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>

Now that the program is attached and running in Immunity Debugger, we can develop our offset finder script. We will use our fuzzing script as a base and make some changes to it to find the EIP Offset. Before we can get to that, we will generate a random patter using Metasploit Framework’s **pattern_create.rb** script. This will generate a random patter that we can use to calculate the exact offset of the EIP. To accomplish this task, we will use the following command:
```console
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
```
<a href="/images/pattern_create.png"><img src="/images/pattern_create.png"></a>

Shown in the screenshot below is the script we will use to perform the offset finding portion of the test. It makes a connection to the target IP and port, sends the pattern with a return and newline character added, and closes the connection. 

<a href="/images/finder_py.png"><img src="/images/finder_py.png"></a>

We will run this against the binary running on the Windows system using the following command:
```console
python finder.py
```
<a href="/images/finder.png"><img src="/images/finder.png"></a>

As we expected, the program crashes and Immunity Debugger catches the crash; pausing the program execution.

<a href="/images/imdb_3.png"><img src="/images/imdb_3.png"></a>

We can take a closer look at the value located within the EIP on the Registers pane. In this case, the value is 65413765. We will copy this value to our clipboard to calculate the EIP Offset.

<a href="/images/imdb_eip.png"><img src="/images/imdb_eip.png"></a>

We can now use Metasploit Framework’s pattern_offset.rb to calculate the exact offset location of the EIP. This can be done using the following command:
```console
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 300 -q 65413765
```
<a href="/images/pattern_offset.png"><img src="/images/pattern_offset.png"></a>

Shown in the screenshot above is the exact EIP Offset location returned by pattern_create.rb. We will now verify that the offset we discovered is correct. This will ensure that we can control program execution by gaining control of the EIP.

#### **Offset Verification**
Since the program crashed in the last step in the testing process, we will re-open and attach it to Immunity Debugger. We will use the same steps previously listed.

<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>

Now that the program is attached and running in Immunity Debugger, we can develop a script to verify the offset value that we previously discovered. Shown in the screenshot below is the script we will use to verify the EIP Offset value. This script will connect to the target IP and port, send 142 “A’s” followed by 4 “B’s” and a return and newline character, then it closes the connection. This will effectively cause the program to crash and overwrite the EIP with **42424242**.

<a href="/images/verify_py.png"><img src="/images/verify_py.png"></a>

We will execute our EIP Offset verification script using the following command:
```console
python verify.py
```
<a href="/images/verify.png"><img src="/images/verify.png"></a>

As expected, the program crashes and Immunity pauses the program execution for further inspection. 

<a href="/images/imdb_4.png"><img src="/images/imdb_4.png"></a>

If we take a closer look at the values located within the EIP, we will see **42424242 (4 “B’s”)**. This means that we now control the EIP. This is important to achieve in the exploit development process because now we can control the programs execution. Ultimately, this will allow us to remotely execute commands on the system. Before we can get to that point, we need to fish out the characters that the program rejects.

<a href="/images/imdb_eip_2.png"><img src="/images/imdb_eip_2.png"></a>

#### **Finding Bad Characters**
This step in the process will allow us to find the characters that the binary rejects (bad characters). We will accomplish by using a script that sends all **255 ASCII characters** in hexadecimal representation to the program at once. It will be fairly obvious to see what characters the program accepts and the ones that it does now. Before we get to that point we will open and attach the binary to Immunity Debugger using the steps previously outlined.
