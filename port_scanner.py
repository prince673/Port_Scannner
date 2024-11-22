from scapy.all import ARP, Ether, srp
import nmap
import requests

def scan_network(ip_range):
    """
    Scans the given IP range for active devices using ARP requests.

    Args:
        ip_range (str): The IP range to scan, in CIDR notation (e.g., '192.168.1.0/24').

    Returns:
        list: A list of dictionaries, each containing the IP and MAC address of an active device.
              Example: [{'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55'}, ...]

    This function constructs an ARP request packet for the specified IP range and sends it
    using Ethernet broadcast. It listens for responses and collects the IP and MAC addresses
    of devices that respond, indicating they are active on the network.
    """
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients


    return clients

def port_scan(target):
    """
    Scans all 65535 ports on the specified target using [nmap](https://nmap.org/) and prints the results.

    Args:
        target (str): The IP address or hostname of the target to scan.

    Returns:
        None: This function prints the scan results directly.
    """
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p-')  # '-p-' scans all 65535 ports
    for host in nm.all_hosts():
        print('Host : ' + host)
        print('State : ' + nm[host].state())
        for proto in nm[host].all_protocols():
            print('Protocol : ' + proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print('port : ' + port + '/' + nm[host][proto][port]['name'])


def check_directory_traversal(url):
    """
    Checks for directory traversal vulnerability by attempting to access the /etc/passwd file.

    Args:
        url (str): The base URL to test for directory traversal vulnerability.

    Returns:
        None: Prints a message indicating whether a directory traversal vulnerability was found.
    """
    payload = "/etc/passwd"
    test_url = url + payload
    response = requests.get(test_url)
    if response.status_code == 200 and "root:" in response.text:
        print(f"Directory traversal vulnerability found at {test_url}")
    else:
        print(f"No directory traversal vulnerability found at {test_url}")


# Example usage
ip_range = " 192.168.31.73"  
# Scan the network for clients within the specified IP range.
clients = scan_network(ip_range)
for client in clients:
    # Print the IP and MAC address of each client found in the network scan.
    print(f"IP: {client['ip']}, MAC: {client['mac']}")

target = '192.168.152.134'
# Perform a port scan on the specified target IP address.
port_scan(target)

url = 'http://192.168.152.132/phpMyAdmin/'
# Check the specified URL for directory traversal vulnerabilities.
check_directory_traversal(url)


# ip_range = " 192.168.31.73"  
# other ip range 