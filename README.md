
# Network Slowdown

## Overview

A threat hunt investigation was conducted regarding a sudden rapid decrease in network speed in a local area network (LAN) working environment. Coordinated and sophisticated attacks seem rather unlikely and may point to endpoint activity within the internal network. The primary tool here used was **Microsoft Defender for Endpoint (MDE)**, while leveraging Kusto Query Language (KQL) to query detailed threat hunting logs to identify large files downloaded, port scans, and numerous failed connection attempts. The findings below highlight the importance of implementing safeguards that will flag any suspicious behaviour from inside the network.


---

## 1. Preparation

### Scenario:

The networking team have noticed a significant decrease in network speed that is mainly affecting the older systems attached to the 10.0.0.0/16 network. This has caused significant slowdown and overall negative performance on the network. DDOS attacks have been ruled out and network engineers are considering that the problem may lie within the endpoints themselves. 

Currently, the traffic originating from the local area network (LAN) is allowed by all endpoints. Applications such as Powershell and others can be used freely by those in the working environment. There are suspicions that a user(s) may be downloading extremely large files or conducting port scans on the internal network. 

### Hypothesis:

All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It's possible someone is either downloading large files or performing a port scan against hosts in the local network.

## 2. Data Collection
  
### Action:

Inspect logs for execessive successful/failed connections from any devices. If discovered, pivot and inspect those devices for any suspicious file or process events.

Ensure the relevant tables contain recent logs:

```kql
- DeviceNetworkEvents
- DeviceFileEvents
- DeviceProcessEvents
```

#### Initial Findings:

The Windows VM, `win-vm-mde` was found failing several connection requests against another host on the same network.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where DeviceName startswith "win-vm-m"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
![image](https://github.com/user-attachments/assets/a2491475-96dd-4997-bad4-0b0a1b6f3108)

---

## 3. Data Analysis

### Findings

After observing failed connection requests from a suspected host `10.0.0.137` in chronological order, we noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

```kql
let IPinQuestion = "10.0.0.137";
DeviceNetworkEvents
| where ActionType == 'ConnectionFailed'
| where LocalIP == IPinQuestion
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/9bf95e1d-0ef7-4bff-ae74-bdb571a326b5)

![image](https://github.com/user-attachments/assets/3dceadab-d92f-4ea4-a9e6-6afb049ad088)

We can see that the first port that was scanned started on `09 June 2025` at `00:30:19` or `2025-06-08T16:30:19.4145359Z`. We pivoted to the `DeviceProcessEvents` table to see if we could see anything suspicious and specified 10 minutes before and after the port scan started. We noticed a PowerShell script named `portscan.ps1` launch at `2025-06-08T16:29:40.1687498Z`.

```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-06-08T16:30:19.4145359Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

```
<img width="1085" alt="Screenshot 2025-06-09 032032" src="https://github.com/user-attachments/assets/dfbc8082-7669-4b29-ad50-61d0a9adc7ab" />


We accessed the suspected computer and found the PowerShell script that was used to conduct a port scan.

<img width="758" alt="Pasted image 20250329134622" src="https://github.com/user-attachments/assets/5d49885c-ea06-4ec3-b459-d741d8b840e2" />

We observed the port scan script was launched by the user `ylavnu`, which is unexpected behaviour and was not authorised by the other administrators. The device was then isolated and scanned for malware. The malware scan produced no results, so out of caution, the device was kept isolated and planned to have it reimaged/rebuilt.

## 4. Investigation

**Suspicious Activity Origin**: An endpoint within the 10.0.0.0/16 network, specifically the Windows VM `win-vm-mde` (IP: 10.0.0.137), initiated unusual activity causing a significant network slowdown, as observed by the networking team on June 09, 2025.

**Potential Reconnaissance**: The sequential scanning of IP addresses within the 10.0.0.0/16 network indicates an attempt to gather information about the internal network, possibly as a precursor to further attacks or to map the environment (T1595.001: Scanning IP Blocks).

**Discovery via Port Scanning**: The device conducted a port scan, systematically targeting sequential ports on other hosts within the LAN, as detected by numerous failed connection attempts in Microsoft Defender for Endpoint logs (T1046: Network Service Discovery), likely to identify vulnerable systems or services.

**PowerShell Execution**: A PowerShell script named `portscan.ps1` was executed on `win-vm-mde` at `2025-06-08T16:29:40.1687498Z`, just before the port scan began, leveraging PowerShell’s capabilities to automate the scanning process (T1059.001: PowerShell).

**Unexpected User Account Usage**: The `portscan.ps1` script was launched by the user `ylavnu`, an action that was unexpected and not authorized by administrators, suggesting possible misuse of user credentials or compromised account
    
    
### MITRE ATT&CK TTPs

1. **Tactic: Reconnaissance (TA0043)** 
    
    - **Technique: Scanning IP Blocks (T1595.001)** Adversaries scan IP blocks to identify targets, often as a precursor to attacks. The scans were done on targeted hosts within the 10.0.0.0/16 network, as seen in failed connection attempts.
 
2. **Tactic: Execution (TA0002)** 
    
    - **Technique: PowerShell (T1059.001)** Adversaries use PowerShell to execute commands or scripts, often for malicious purposes, due to its legitimate use and powerful capabilities. The KQL query on `DeviceProcessEvents` identified `portscan.ps1`, a PowerShell script, launched at `2025-06-08T16:29:40.1687498Z`, just before the port scan.
        
        
3. **Tactic: Privilege Escalation (TA0004)** 
    
    - **Technique: Valid Accounts (T1078)**  Adversaries use legitimate credentials (e.g., compromised or misused) to execute actions. The `portscan.ps1` script was executed by the user `ylavnu`, which was unexpected and not authorised by administrators.
  
4. **Tactic: Discovery (TA0007)** 
    
    - **Technique: Network Service Discovery (T1046)** Adversaries use port scanning to identify open ports and services on target hosts within the network. The KQL query on `DeviceNetworkEvents` revealed that the failed connection attempts from `10.0.0.137` targeted ports in a sequential and chronological pattern, focusing on commonly used ports. This behavior strongly indicates a methodical port scan conducted around `2025-06-08T16:30:19.4145359Z`.

---

## 5. Response

### Actions Taken
- Immediately isolated the compromised VM from the network to prevent further scanning or lateral movement.

- Performed a thorough malware scan and forensic investigation to identify persistence mechanisms or additional malicious activity.

- Investigate why the user `ylavnu` launched the PowerShell script and tighten controls on privileged account access to prevent misuse.

- Configured the firewall to block suspicious outbound or inbound traffic from the endpoint, especially unusual or sequential port connection attempts.

- Deployed IDS/IPS solutions that can detect and block port scanning and other reconnaissance activities in real-time.

## 6. Improvement

### Prevention:
- **Network Segmentation and Egress Controls**: Segment the internal network to limit lateral movement and reconnaissance scope. Implement network egress filtering to block unauthorized scanning and connection attempts within the LAN.
- **PowerShell Restrictions**: Place PowerShell into Constrained Language Mode, reducing risk of executing malicious scripts.
- **Real-Time Alerting**: Use Endpoint Detection and Response (EDR) tools and Intrusion Detection/Prevention Systems (IDS/IPS) to monitor for suspicious PowerShell executions and sequential port scanning activity. Configure alerts for unusual user activity, especially involving scripting or network scanning.

### Threat Hunting:
- Use KQL queries to detect PowerShell scripts related to port scanning or network reconnaissance, focusing on command lines invoking TCP connection attempts or scanning utilities.
- Correlate  `DeviceNetworkEvents` and `DeviceProcessEvents` to identify processes (like portscan.ps1) that precede or coincide with sequential failed connection attempts, indicating scanning behavior.
- Regularly audit changes to user privileges especially unauthorised privilege escalations or scripting capabilities by users like `ylavnu`.
- Establish normal user and network behavior baselines to detect deviations such as unusual PowerShell usage or network scanning patterns originating from endpoints.

---

## Conclusion

Port scanning is one of the most common techniques used to assess a target’s security posture. Sequential and chronological scanning patterns are relatively straightforward to detect. Maintaining continuous monitoring through firewalls and IDS/IPS solutions is critical to prevent threat actors from gaining a foothold. Fortunately, in this case, the connection attempts were unsuccessful, and the opportunity to exploit any open ports was effectively thwarted.


