# Network Security Tools Collection

This repository contains a comprehensive collection of network security and penetration testing tools. These tools are grouped into various categories for easier navigation and usage. This project is designed to aid penetration testers, security professionals, and cybersecurity enthusiasts in performing tasks like network scanning, vulnerability exploitation, password cracking, phishing, Wi-Fi cracking, DDoS testing, and more.

## Overview

The tools in this collection are divided into the following categories:

### 1. **Network Scanners**:
Tools for discovering devices, services, and open ports in a network.

- **Nikto**: Web server scanner that detects vulnerabilities like outdated software versions, security issues, and configuration problems.
- **SqlMap**: A powerful tool for automatic SQL injection and database takeover.
- **Wfuzz**: Web application fuzzer used to brute-force web applications and APIs.
- **WhatWeb**: Identifies various technologies used by a website, including web servers, frameworks, and CMS platforms.
- **WafWoof**: A tool for discovering Web Application Firewalls (WAF) protecting a site.

### 2. **Reconnaissance Tools**:
Tools for gathering information about the target system, including DNS, WHOIS, and port scanning.

- **Nmap**: The most widely used network mapper to discover hosts and services on a computer network.
- **Scanner**: Custom scripts for scanning open ports and discovering services in a network.
- **DNSEnum**: A DNS enumeration tool for gathering DNS information.
- **Whois**: A tool for obtaining information about domain registration and ownership.

### 3. **Exploitation Tools**:
Tools used for exploiting vulnerabilities found in systems.

- **Metasploit**: An advanced exploitation framework for developing and executing exploits against remote targets.
- **MSFVenom**: A tool within the Metasploit framework used for creating payloads that can be used in exploits.
- **SearchSploit**: A tool for searching Exploit-DB, a massive repository of exploits.
- **ExploitDB**: Another way to search and leverage publicly available exploits.

### 4. **Wi-Fi Cracking Tools**:
Tools for attacking and cracking Wi-Fi networks.

- **Aircrack-ng**: A toolset for attacking Wi-Fi networks by cracking WEP and WPA-PSK keys.
- **Kismet**: A network detector, sniffer, and intrusion detection system for 802.11 wireless LANs.
- **Wifite**: Automated Wi-Fi hacking tool for cracking WEP and WPA networks.
- **Wash**: A tool used to detect WPS-enabled Wi-Fi networks and perform brute-force attacks.

### 5. **Password Cracking Tools**:
Tools designed for cracking hashed passwords.

- **Hydra**: A fast and flexible password-cracking tool supporting various protocols such as HTTP, FTP, SSH, and more.
- **Medusa**: A parallel and modular login brute-forcer.
- **JohnTheRipper**: A powerful password-cracking tool with support for many hash algorithms.
- **Hashcat**: Advanced password recovery and cracking tool with GPU acceleration.

### 6. **Sniffing Tools**:
Tools for capturing and analyzing network traffic.

- **Tcpdump**: A packet analyzer that lets you capture network traffic in real-time.
- **Wireshark**: A graphical network protocol analyzer for monitoring network traffic in real-time.
- **Ettercap**: A comprehensive suite for man-in-the-middle attacks, sniffing, and injecting packets into a network.

### 7. **DDoS Tools**:
Tools for testing the robustness of a network under Distributed Denial of Service (DDoS) attacks.

- **Hulk**: A DoS tool designed to generate massive traffic to overwhelm a web server.
- **GoldenEye**: Another DDoS testing tool that simulates attacks on web servers.
- **OtherTools**: Additional tools for DDoS attacks and performance testing.

### 8. **Social Engineering Tools**:
Tools used for social engineering attacks such as phishing, email spoofing, fake websites, and SMS spoofing.

- **Phishing**: Tools for creating and launching phishing attacks (e.g., fake login pages).
- **Email**: Tools for creating and sending phishing emails to deceive the target into revealing sensitive information.
- **Fake Website**: A tool for generating a fake website to trick users into entering credentials or sensitive information.
- **SMS Spoofing**: Tools for sending SMS messages with spoofed sender information to deceive recipients.

## Dependencies

This project requires several external libraries and tools. Below are the necessary installations:


### 1. **Python Dependencies**:


Install Python 3.x and pip, if you haven't already.

Use `pip` to install the following Python libraries:

```bash
pip install flask requests beautifulsoup4 dnspython twilio

### 2. **Other Tools** :

Some tools in this project need to be installed separately. Follow the installation instructions below for each tool:

- **Metasploit**: Install Metasploit Framework. Follow the [official installation guide](https://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework).
- **Nikto**: Install Nikto by following the instructions on [GitHub](https://github.com/sullo/nikto).
- **SqlMap**: Install SqlMap by following the guide on [GitHub](https://github.com/sqlmapproject/sqlmap).
- **Wireshark**: Download Wireshark from the [official website](https://www.wireshark.org/download.html).
- **Hydra**: Install Hydra using the [installation guide](https://github.com/vanhauser-thc/thc-hydra).
- **JohnTheRipper**: Install JohnTheRipper by following instructions on [GitHub](https://github.com/magnumripper/JohnTheRipper).
- **Aircrack-ng**: Install Aircrack-ng by following the [installation guide](https://www.aircrack-ng.org/).


### 3. Required System Tools:

These tools can be installed via the package manager:

- **Nmap**: Install via package manager:
    ```bash
    apt-get install nmap
    ```
    or
    ```bash
    yum install nmap
    ```

- **Hydra**: Install via package manager:
    ```bash
    apt-get install hydra
    ```
    or
    ```bash
    yum install hydra
    ```

- **JohnTheRipper**: Install via package manager:
    ```bash
    apt-get install john
    ```
    or
    ```bash
    yum install john
    ```

### 4.License:

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 5.Ethical Usage Warning:

This project is intended for **educational purposes only**. The tools and scripts included are powerful and can be used to conduct various types of penetration testing, network scanning, and other security assessments. However, it is crucial to remember the following:

- **Only use these tools in authorized environments.**
- **Do not attempt to access networks, systems, or applications without explicit permission.**
- Engaging in activities like unauthorized scanning, exploiting vulnerabilities, or performing DDoS attacks is illegal and unethical.

Always follow ethical guidelines and ensure you have written consent before performing any security tests on a network or system.

By using this project, you agree to use it responsibly and legally. The author and contributors are not responsible for any illegal activities conducted using this code.
