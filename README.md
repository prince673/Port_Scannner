# Network Scanner and Directory Traversal Checker

This project consists of a Python script that scans the network for active devices and checks for directory traversal vulnerabilities in a given URL.
This README file provides a brief overview of the project, lists the requirements, setup instructions, and usage information. It also includes a section for contribution and license information.

Make sure to replace the placeholders ('192.168.31.73', '192.168.152.134', and 'http://192.168.152.132/phpMyAdmin/') with the actual values you want to scan and test.

Remember to install the required libraries mentioned in the setup section before running the code

## Requirements
- Python 3.x
- `scapy` library
- `nmap` library
- `requests` library

## Setup
1. Install the required libraries using the following command:
2. Make sure you have the necessary permissions to perform network scans on the target network.

## Usage
1. Open the `main.py` file and replace `'192.168.31.73'` with the actual IP range you want to scan.
2. Replace `'192.168.152.134'` with the target IP address for the port scan.
3. Replace `'http://192.168.152.132/phpMyAdmin/'` with the base URL you want to test for directory traversal vulnerabilities.
4. Run the `main.py` file to perform the network scan and check for directory traversal vulnerabilities.

project_directory/
    README.md
    LICENSE
    requirements.txt
    main.py
    tests/
        test_network_scanner.py
        test_directory_traversal.py
    docs/
        index.md

        
## Contribution
Feel free to contribute to this project by creating pull requests or reporting issues.

## License
This project is licensed under the MIT License.

