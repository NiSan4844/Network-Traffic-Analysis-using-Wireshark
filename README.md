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


# Network Traffic Analysis Project - RDP Traffic Analysis 

This guide walks through the process of analyzing Remote Desktop Protocol (RDP) traffic using Wireshark, including filtering, decrypting, and analyzing the data from a `.pcapng` file.

## Steps for RDP Traffic Analysis

### Task #1: Open the `.pcapng` File in Wireshark

1. Unzip the provided file and open the `rdp.pcapng` file in Wireshark.
2. Familiarize yourself with the traffic captured in the file.

### Task #2: Analyze the Traffic

1. **Initial Inspection**: Begin by observing the traffic. Notice that the data is encrypted and not much information is immediately visible.
2. **Filter on RDP**: Use the `rdp` filter in Wireshark to look for any RDP-specific traffic.
    ```bash
    rdp
    ```

    ![S1 rdp](https://github.com/user-attachments/assets/5662e8f6-f788-434b-9bf4-46b6993a9a9b)

3. **Verify RDP Traffic via TCP Port 3389**: RDP typically uses TCP port 3389. To verify if RDP traffic exists in the capture, apply a display filter:
    ```bash
    tcp.port == 3389
    ```
4. **Confirm Session Establishment**: By filtering on `tcp.port == 3389`, you should see a TCP session established between the two hosts over port 3389.

    ![S1 session established](https://github.com/user-attachments/assets/1f89a21d-1455-4f83-94e6-70465c352ecb)

### Task #3: Decrypt the Traffic

1. **Obtain the RSA Key**: To decrypt the encrypted RDP traffic, you need the RSA private key for the server. For this example, the key is included (`server.key`).
2. **Import the Key into Wireshark**:
   - Navigate to **Edit** → **Preferences** → **Protocols** → **TLS**.
   - Select **Edit** under the **RSA Keys List** section.
   - Click **+** to add a new key:
     - **IP Address**: 10.129.43.29 (RDP server IP)
     - **Port**: 3389
     - **Protocol**: Leave blank or set to `tpkt`
     - **Key File**: Browse to and select `server.key`.
   - Click **Save** and refresh the `.pcapng` file.
        
     ![S1 session established](https://github.com/user-attachments/assets/247c6c06-7ab4-405c-8ad3-ec3b10a4cfad)

3. **View Decrypted RDP Traffic**: Once the key is added, apply the `rdp` filter again, and now you should see decrypted RDP traffic in the clear.

    ![S4 rdp in the clear](https://github.com/user-attachments/assets/47bbeef3-5476-4d42-a6cd-1d8f4f885ad9)

### Task #4: Perform Analysis on the Decrypted Traffic

1. **Inspect TCP Streams**: Now that the traffic is decrypted, you can analyze TCP streams, follow conversations, and investigate user activity.
2. **Follow TCP Stream**: Right-click on an RDP packet and select **Follow TCP Stream** to view the detailed session.
3. **Analyze User Actions**: Look for signs of interaction with the host, including user commands and actions.
4. **Extract Objects**: If necessary, export any objects or files from the session for further investigation.

    ![S5 Observe ACII](https://github.com/user-attachments/assets/5284123b-5ba8-4aa8-8fee-56d352b2733b)

### Questions & Answers

#### 1. What host initiated the RDP session with the server?

- The host that initiated the RDP session is **10.129.43.27**. This can be identified from packet #8 of the three-way handshake.

#### 2. Which user account was used to initiate the RDP connection?

- The user account used for the RDP session can be found by examining the record labeled **Ignored Unknown Record** when filtering on `tcp.port == 3389`. The username is visible in the ASCII output which is `bucky`.

### Summary

This exercise demonstrated how to analyze encrypted RDP traffic using Wireshark by:
- Filtering RDP traffic over port 3389.
- Decrypting traffic with the RSA key.
- Analyzing user actions by following TCP streams.
  
Wireshark is a powerful tool that allows cybersecurity professionals to decrypt and analyze various protocols, assuming the required keys are available. This capability can be extended to other encrypted traffic, providing insight into network activity for incident response and analysis.

