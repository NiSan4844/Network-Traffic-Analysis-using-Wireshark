# Network Traffic Analysis Project - Suspicious Traffic Investigation

## Project Summary
This project involved investigating suspicious network traffic originating from a specific host within the network. We used Wireshark to analyze PCAP files and identified malicious activity, which led to the infiltration of a host, user creation with elevated privileges, and suspicious commands being executed.

## Scope and Goal
- **Target Host:** 10.129.43.4
- **Timeframe:** Last 48 hours
- **Goal:** Capture and analyze traffic to determine the nature of suspicious activities related to the host and investigate any connections to other hosts.

  ![S1](https://github.com/user-attachments/assets/024e9b4a-fc44-4339-9fe3-e59cd6b90eb2)

  ![S2 Conversation plugin](https://github.com/user-attachments/assets/aed2f9e6-7ab2-47cb-b3a1-6eef51942e52)

  ![S3 Protocol Heirarchy](https://github.com/user-attachments/assets/ba4cd9f7-7fd0-4cb5-b62c-f731f10ca92d)


## Target(s)
- **Network:** 10.129.43.0/24
- **Hosts:** 10.129.43.4, 10.129.43.29
- **Protocols:** TCP and UDP (focus on unknown protocol over port 4444)

## Capture and Analysis Approach
### Filtering Network Traffic
1. **Initial Filter:** Focused on traffic involving host 10.129.43.4.
2. **UDP Traffic Filtering:** 
   - Found only nine packets (ARP, NAT, SSDP) which were deemed normal traffic.

      ![S4 !tcp](https://github.com/user-attachments/assets/7b5e509b-781d-4f1a-bf98-5401902af41c)

3. **TCP Traffic Filtering:**
   - Filtered out everything except TCP traffic using the filter `!udp && !arp`.

       ![S5 !udp   !arp](https://github.com/user-attachments/assets/de3bc4e4-6e1a-4682-bb4e-9aaadbe30868)

   - Discovered a suspicious TCP session between 10.129.43.4 and 10.129.43.29, established via a three-way handshake in packet 3. 

      ![S6 TCP Handshake](https://github.com/user-attachments/assets/f8de4332-4195-40ff-be5a-9752722cd6e7)

   - The session did not show signs of termination (no TCP teardown or reset packets), indicating it may still be active.

### TCP Stream Analysis
- **Followed the TCP Stream:** Revealed suspicious activity in plain text, where someone was executing reconnaissance commands (e.g., `whoami`, `ipconfig`, `dir`) to gather information on the host.

    ![S7 follow tcp stream](https://github.com/user-attachments/assets/25100f98-2a3b-4f95-b106-b4d1a7bfd44a)


- **Malicious User Creation:** Detected the creation of an account called "hacker" and its addition to the administrators group on the host. This indicates that the network was infiltrated, and administrative privileges were assigned to an unauthorized user.

    ![S8 Sus](https://github.com/user-attachments/assets/0c6ec089-9569-4b13-8c5f-0bb340648679)


## Key Findings and Results
- **Hosts Affected:** 
  - Host 10.129.43.29 was infiltrated by a malicious actor who executed commands and created an administrative account.
  - The actor used Bob’s host for these actions, and Bob was previously investigated for exfiltrating corporate secrets disguised as web traffic.
- **Malicious Activity:** The actor issued commands through a Netcat shell to control Bob’s host and attempted to use RDP to establish another foothold on a separate Windows desktop in the environment.

### Summary of the Analysis
The analysis revealed that a malicious actor has infiltrated the network and compromised host 10.129.43.29. The actor used Bob's host to create an administrator-level account and performed reconnaissance. The intrusion likely spread further through RDP to other systems. Immediate Incident Response (IR) procedures were recommended to prevent the threat from spreading further.

## Conclusion
A full Incident Response (IR) procedure was initiated after quarantining Bob’s host. PCAP files capturing RDP traffic were analyzed, and further investigation into compromised hosts is ongoing.

## Recommendations
- **Host Quarantine:** Quarantine any affected hosts to prevent further lateral movement.
- **Incident Response:** Initiate a full Incident Response process to contain and mitigate the threat.
- **Review Network Logs:** Conduct a thorough review of network logs and security controls to identify other potentially compromised systems.
