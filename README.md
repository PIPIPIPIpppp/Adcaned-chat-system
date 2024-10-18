# Group 41 Secure Chat System


Group Members

1.Lochlan Jarvinen

2.Yaqi Peng

3.Brooke Seigert

4.Juniper Worrall



### Overview

This project is a secure chat system developed as part of an advanced secure programming assignment.
It features a client-server architecture with end-to-end encryption, message integrity verification, 
and user authentication. The system is designed to comply with the OLAF/Neighbourhood protocol v1.2, 
integrating advanced cryptographic practices like RSA and AES.



### Features

1. User registration and Authentication
2. Listing Online Members
3. Private Messaging Between Members
4. Global Messaging to All Participants
5. Group Messaging to Specified Users
6. Point-to-point File Transfer
7. Encryption of All Communications
8. Digital Signatures for Message Integrity
9. Intentional (ethical) Backdoors for Security Testing



### Prerequisites

C language compiler (GCC Recommended)

OpenSSL

cJSON



### Installing OpenSSL & cJSON

For Unix run the following command line:
sudo apt install libssl-dev libcjson-dev

For Windows a package manager is reconmended for installation. (vcpkg Recommended)
Using vcpkg install the prerequisites with the following command line:
vcpkg install cjson openssl



### Compilation and Startup
									
First start an instance of the server

1. Navigate to the project directory

2. Compile the server code e.g. using gcc
gcc -o server server.c -pthread -lssl -lcrypto

3. Run the server by specifying the port number (e.g., 8080)
./server 8080

Now the server should be running and listen for connections on the specified port.

Next running the client

1. Open a new terminal window

2. Navigate to the project directory

3. Compile the client code e.g. using gcc
gcc -o client client.c -pthread -lssl -lcrypto

4. Run the client by providing the server’s IP address and port number (e.g., 127.0.0.1 and 8080)
./client 127.0.0.1 8080


	  
### Available User Commands

Public [message]

Sends a message to everyone.

Private [message]

Sends a private message. After entering your message you then be prompted
to enter a recipient address e.g. e.g. 192.168.0.101 
For multiple addresses, separate addresses with commas e.g. 192.168.0.101, 192.168.0.102

list members

Returns a list of the connected members



### Known Vulnerabilities

The code labeled vulnerable contains at least three intentional security flaws.


### Please navigate to the vulnerable tree for code with backdoors.
### Navigate to not-vulnerable tree for code with no backdoors.
