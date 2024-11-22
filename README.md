This Python-based cybersecurity utility is designed to perform three essential tasks: network scanning, port scanning, and basic vulnerability assessment for directory traversal. This tool is ideal for ethical hackers and cybersecurity enthusiasts looking to analyze and secure their networks.

Features 📋
Network Scanning

Uses ARP requests to discover active devices within a specified IP range.
Retrieves IP and MAC addresses of connected devices.

Port Scanning

Leverages the Nmap library to perform comprehensive scans on all 65,535 ports of a target.
Displays open ports and associated services.
Example Output:
makefile
Copy code
Host: 192.168.1.1
State: up
Protocol: TCP
Port: 22/ssh
Port: 80/http
Directory Traversal Vulnerability Check

Tests web servers for directory traversal vulnerabilities by attempting to access sensitive files like /etc/passwd.
Example Output:
php
Copy code
Directory traversal vulnerability found at http://example.com/../../etc/passwd
No directory traversal vulnerability was found at http://example.com/
Getting Started 🚀
Prerequisites
Python 3.x
Required Python Libraries:
Install them using the following command:
bash
Copy code
pip install scapy python-nmap requests
Usage
Network Scanning
Scan a specified IP range to discover active devices.

Python
Copy code
clients = scan_network('192.168.1.0/24')
for a client in clients:
    print(f"IP: {client['ip']}, MAC: {client['mac']}")
Port Scanning
Could you perform a port scan on a specific target IP?

Python
Copy code
port_scan('192.168.1.1')
Directory Traversal Test
Check if a web server is vulnerable to directory traversal attacks.

python
Copy code
check_directory_traversal('http://example.com/')
Use Cases 🎯
Identify devices and their MAC addresses on a network.
Assess open ports and running services for vulnerabilities.
Test web servers for directory traversal exploits.
