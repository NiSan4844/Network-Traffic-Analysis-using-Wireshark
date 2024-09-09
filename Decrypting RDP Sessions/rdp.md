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
3. **Verify RDP Traffic via TCP Port 3389**: RDP typically uses TCP port 3389. To verify if RDP traffic exists in the capture, apply a display filter:
    ```bash
    tcp.port == 3389
    ```
4. **Confirm Session Establishment**: By filtering on `tcp.port == 3389`, you should see a TCP session established between the two hosts over port 3389.

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
3. **View Decrypted RDP Traffic**: Once the key is added, apply the `rdp` filter again, and now you should see decrypted RDP traffic in the clear.

### Task #4: Perform Analysis on the Decrypted Traffic

1. **Inspect TCP Streams**: Now that the traffic is decrypted, you can analyze TCP streams, follow conversations, and investigate user activity.
2. **Follow TCP Stream**: Right-click on an RDP packet and select **Follow TCP Stream** to view the detailed session.
3. **Analyze User Actions**: Look for signs of interaction with the host, including user commands and actions.
4. **Extract Objects**: If necessary, export any objects or files from the session for further investigation.

### Questions & Answers

#### 1. What host initiated the RDP session with the server?

- The host that initiated the RDP session is **10.129.43.27**. This can be identified from packet #8 of the three-way handshake.

#### 2. Which user account was used to initiate the RDP connection?

- The user account used for the RDP session can be found by examining the record labeled **Ignored Unknown Record** when filtering on `tcp.port == 3389`. The username is visible in the ASCII output.

### Summary

This exercise demonstrated how to analyze encrypted RDP traffic using Wireshark by:
- Filtering RDP traffic over port 3389.
- Decrypting traffic with the RSA key.
- Analyzing user actions by following TCP streams.
  
Wireshark is a powerful tool that allows cybersecurity professionals to decrypt and analyze various protocols, assuming the required keys are available. This capability can be extended to other encrypted traffic, providing insight into network activity for incident response and analysis.