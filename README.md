# Polysphere Temp Blog

---

## POST

Hehehe tor go funny

This post will go through the vulnerabilites of tor/torbrowser, onion balance and the stem library 
The vulnerabilties might not directly affect the onion relay protocol 

————————————————

Tor/TorBrowser

The Tor/Torbrowser in total have 41 combined found vulnerabilties 
We will only be going over the important vulns I think is interesting

‎scripts/test/appveyor-irc-notify.py
CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
Calling to a deprecated function like ssl.wrap_socket doesnt entirely specify the protocol and can result in an insecure default being used
Some ways we can try preventing this is avoiding calling ssl.wrap_socket without specifying the ssl_version

Blabber
Using ssl.wrap_socket without specifying the ssl_version can lead to an outdated and weak security protocol It's crucial to encrypt sensitive data for protection Encryption standards need to stay current because attackers keep getting better at breaking them So your encryption should always be up to date and strong enough for the type of data you have

‎scripts/maint/add_c_file.py
CWE-23 (https://cwe.mitre.org/data/definitions/23.html)
Unsanitized input from a command line argument flows into open where it used as a path so it can become a path traversal vulnerability that can allow someone to write arbitrary files
With a vulnerability like this we can do something known as a directory traversal attack which main purpose is to access files and directories that are stored outside the intended folder
In this example it is a Zip-Slip type vulnerability that allows us to create and replace existing files which we can use something like this

curl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa

That will allow use to leak the private key of root and then using a malicious zip archive that holds path traversal filenames then when the zip archive is extracted it will result in traversing out the target folder and ending up in a /root/.ssh/ directory for example

torbrowser_launcher/common.py
CWE-502 (https://cwe.mitre.org/data/definitions/502.html)

Unsantized input from a command line argument flows into pickle.load where it can result in unsafe deserialization vulns
The vulnerability that can be found here is a process of converting an object into a sequence of bytes that can persist to a disk or database that can be sent through streams


————————————————

Onionbalance V3

This has a total of 20 reps and its primary function is to allow tor onion service requests to be distributed across multiple backend tor instances
and it provides load balancing while also making onion services more resilient and reliable by elimating single points of failure

versioneer.py:393
CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
Unsanitized input from command line argument flows into subprocess.popen that can result in a command injection vulnerability
The vulnerability can be done by using an OS command injection attack that allows users to pass commands directly to the system shell attached to a legit request

————————————————

Stem (Python Tor Library)

This rep has 27 vulnerabilities
Stem is a Python controller library for Tor With it you can use Tor's control protocol to script against the Tor process or build things such as Nyx

docs/_static/example/words_with.py
CWE-400 (https://cwe.mitre.org/data/definitions/400.html)
User input from user input flows into re.compile can have a result of a ReDOS vuln
This vulnerability is mainly surrounded around the regex engine that uses regular expressions to make a system inaccessible to users
It can be done by using a regex regular expression string that includes 14 C's that the engine needs to take over 65k steps just to see if the string is a valid string
it will cause the CPU to be overloaded and work very slowly becoming a DOS

————————————————

---

## ANNOUNCEMENT

We're potentially looking into Quantum resilient encryption

With the upcoming IBM osprey quantum computers it is more prevalent that quantum computers can begin having the computing power to decrypt our encryption/obfuscation

————————————————

Why do we need it?

Quantum computers that use qubits that compute with superpositions of 0 and 1 can be more powerful and faster than any modern-day system

that would allow them to do mathematical computations that would take years in a realistic and reasonable time

————————————————

How do we implement it? (simplified)

but in simpler terms we can use NTRU which is a open source public key cryptosystem and uses lattice cryptography to encrypt/decrypt data

it uses 2 algorithms and it is resistant to attacks using the Shors algorithm 
In the post-quantum cryptography standardization project, it came 3rd but it has the equivalent cryptographic strength as RSA but also performs private key operations faster than RSA

 Heres an example script with NTRU in use

from ntru import NtruEncrypt
ntru = NtruEncrypt(NtruEncrypt.generate_polynomial(167))
public_key, private_key = ntru.generate_key_pair()
message = "Hello, world!"
encrypted_message = ntru.encrypt(message, public_key)
decrypted_message = ntru.decrypt(encrypted_message, private_key)
print(decrypted_message)

The script will make a new NtruEncrypt object with a certain polynomial ring and create a new public/private key pair from that polynomial ring
then encrypts the message and decrypts it with the NTRU algorithms

————————————————

What will it actually look like? (full)

We can implement it similarly to Signal which adds Quantum resistant encryption to their E2EE messaging protocol

In theory, we should be able to create a similar result when it comes to signals messaging encryption but instead, we will try to implement cryptography from the quantum resilient FID02 security key implementation part of the OpenSK open source key firmware that is optimized to use a Dilithium Hybrid signature that benefits from the security of ECC against standard attacks and dilithium resilience against quantum attacks
to create a way more secure process when it comes to the anonymity of our infrastructure

Our choice for the Google FID02 key is because it comes from a company that actually understands how to make quantum computers but has also already created an integrated method with Chrome's support for TLS with the hybrid Kyber KEM

This isn't our final choice in the Quantum Resilience but it is the first one that peeks interest

————————————————

Stop blabbering

Basically what we are doing is trying to prevent any Quantum computer from being able to crack our encryption between the Host, client, etc when it comes to our infrastructure
as technology advances, we must advance with it to make a better, more private, and secure product

————————————————

References and sources

https://security.googleblog.com/2023/08/toward-quantum-resilient-security-keys.html
https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html
https://www.bleepingcomputer.com/news/security/signal-adds-quantum-resistant-encryption-to-its-e2ee-messaging-protocol/
https://signal.org/blog/pqxdh/
https://signal.org/docs/specifications/pqxdh/
https://en.wikipedia.org/wiki/NTRU

---

## POST
Summary: Argonhosting is a cheap hosting service that advertises powerful ddos protection, good security, and good hosting 


————————————————

MISTAKE 1 Ip history 
They tried protecting their server by putting cloudflare UAM on it but it makes no difference because we are able to look up the IP History of the domain and you can clearly see the origin server that hosted the server before cloudflare was put on 

————————————————

MISTAKE 2 UFW 
They didn’t enable UFW so the host/domain can easily be found with related servers including the origin servers 
This allows us to get a lot of information of the host without doing any work but if it had UFW properly setup it would be a different story 

————————————————

MISTAKE 3 MariaDB 
Going back to the UFW mistake we can find the server that contains the database 
With finding the server we can portscan or find the port that receives the database information/OS information 
In this instance we made a special request to get the information of the server which came to this

3306 / TCP
MariaDB10.6.12-MariaDB-0ubuntu0.22.04.1
MariaDB:
  Protocol Version: 10
  Version: 10.6.12-MariaDB-0ubuntu0.22.04.1
  Capabilities: 63486
  Server Language: 45
  Server Status: 2
  Extended Server Capabilities: 33279
  Authentication Plugin: mysql_native_password

MariaDB is a fork of MySQL as MySQL is quite old so it still has the same exploits or vulnerabilities 
A vulnerability we can exploit is a mariaDB/MySQL DB password brute force which looks like this 

Warning: MaxLen = 8 is too large for the current hash type, reduced to 5
words: 16382  time: 0:00:00:02  w/s: 6262  current: citcH
words: 24573  time: 0:00:00:04  w/s: 4916  current: rap
words: 40956  time: 0:00:00:07  w/s: 5498  current: matc3
words: 49147  time: 0:00:00:09  w/s: 5030  current: 4429
words: 65530  time: 0:00:00:12  w/s: 5354  current: ch141
words: 73721  time: 0:00:00:14  w/s: 5021  current: v3n
words: 90104  time: 0:00:00:17  w/s: 5277  current: pun2
[*] Cracked! --> pass
words: 98295  time: 0:00:00:18  w/s: 5434  current: 43gs
Session aborted

The other vulnerabilities are as listed (MariaDB/MySQL Related):
CVE:2012-5627
CVE:2013-1861

————————————————

 MISTAKE 4 Common Vulns 
Returning to the fact the origin server and host related servers are exposed you can find CVE’s that are related to the hardware or server 

These are the CVE’s they’re vulnerable to:
CVE-2021-23017
CVE-2021-3618

---

## ANNOUNCEMENT

I am deciding to remake PolyC2 with golang and python

the new polyC2 listener and payload will be made in golang through ZeroMq protocol and architecture. While the Webserver and API will be made in pypy3 (python) using socketify 

WHY USE ZEROMQ??
https://zeromq.org/

Speed and performance:
Zeromq is a very low-level fast asynchronous messaging library that can handle large amounts of connections and requests under seconds. It was able to get a transfer rate of 10,000 messages per 15 milliseconds, or between 66,000 and 70,000 messages/s under low-latency and it was able to beat rabbitmq , kafka and many other network libraries. ZeroMq fast transfer rates and handling along with golang's effecient concurency and multithreading will make the C2 faster than ever

Lightweight and Efficient:
zeromq lightweight and low level library made in C++ uses as little resources as possible while maintaining the best performance

Security:
zeromq uses CurveZMQ which is an authentication and encryption protocol for ZeroMQ. This can be used to authenticate and encrypt C2 comms fending off network analyst. Zeromq also uses zmtp which is special type of protocol used for communication. 

Load balancing :
ZeroMq has a builtin load balancer, more workers will increase performance in the cost of resources.

———————————————————————————

PolyC2's Webserver and API will be handled by socketify. 

https://github.com/cirospaciari/socketify.py

Socketfiy is focussed on speed and simplicity , and its easy for developers to configure and use socketify. Socketfiy is very fast and faster than gin(golang), fiber(golang), django and fastapi. Socketify pypy3 is able to handle lots of requests per seconds and send over millions of request per seconds. Socketify makes it the ultimate web framework for C2 api and webservers. 

———————————————————————————

NOTE: This is a will be a very long term project and requires tons of research and time to build and optimization for the best performance, If you have any enquiries please feel free to dm me.


peace -@nullsyn

---
