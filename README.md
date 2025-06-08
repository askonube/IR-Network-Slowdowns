
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

The Windows VM, win-vm-mde was found failing several connection requests against another host on the same network.

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

After observing failed connection requests from a suspected host (10.0.0.137) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

```kql
let IPinQuestion = "10.0.0.137";
DeviceNetworkEvents
| where ActionType == 'ConnectionFailed'
| where LocalIP == IPinQuestion
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/9bf95e1d-0ef7-4bff-ae74-bdb571a326b5)

![image](https://github.com/user-attachments/assets/3dceadab-d92f-4ea4-a9e6-6afb049ad088)

We can see that the first port that was scanned started on 09 June 2025 at 00:30:19 or 2025-06-08T16:30:19.4145359Z. We pivoted to the DeviceProcessEvents table to see if we could see anything suspicious and specified 10 minutes before and after the port scan started. We noticed a PowerShell script named portscan.ps1 launch at 2025-06-08T16:29:40.1687498Z.

```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-06-08T16:30:19.4145359Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

```
<img width="973" alt="Screenshot 2025-06-09 014536" src="https://github.com/user-attachments/assets/2ad379da-fa9b-4bf7-b28c-4fc1e5ea6787" />


I logged into the suspect computer and observed the PowerShell script that was used to conduct a port scan.

<img width="758" alt="Pasted image 20250329134622" src="https://github.com/user-attachments/assets/5d49885c-ea06-4ec3-b459-d741d8b840e2" />

We observed the port scan script was launched by the SYSTEM account, which is unexpected behaviour and was not configured by the other administrators. I isolated the device and ran a malware scan. 

On the security.microsoft.com website, I isolated the suspected device and ran an antivirus scan. The malware scan produced no results, so out of caution, we kept the device isolated and put in a ticket to have it reimage/rebuilt.

## 4. Investigation

- John, an employee with privileged access, used PowerShell scripts (T1059.001) to silently install 7-Zip (T1105), a compression utility.

- He continuously archived and moved the files to backup folders, which may serve as a method to hide or remove original data (T1070.004), complicating detection efforts.
    
- He compressed sensitive employee data into ZIP archives (T1560.001) as part of local data staging (T1074), consolidating files in preparation for potential exfiltration.
    
    
### MITRE ATT&CK TTPs

1. **Tactic:** Command and Scripting Interpreter: PowerShell (T1059.001)
    
    - **Technique:** PowerShell was used to silently install 7-Zip and create ZIP archives. This suggests malicious use of PowerShell for script execution to automate data collection and compression.
        
2. **Tactic:** Archive Collected Data: Archive via Utility (T1560.001)
    
    - **Technique:** The use of 7-Zip to compress data into an archive aligns with this technique, where data is collected and compressed before potential exfiltration.
        
3. **Tactic:** Data Staged (T1074)
    
    - **Technique:** Data was staged locally by creating ZIP archives of sensitive employee data, consolidating files into a central location prior to exfiltration. This staging often involves interactive command shells or scripts (e.g., PowerShell) to gather, compress, and prepare data for transfer, minimizing detection risk.
        
4. **Tactic:** Indicator Removal on Host: File Deletion (T1070.004)
    
    - **Technique:** The consistent archiving and moving of files to backup folders may indicate attempts to obscure or stage data, potentially to avoid detection by removing or hiding original files.
        
5. **Tactic:** Ingress Tool Transfer (T1105)
    
    - **Technique:** The silent installation of 7-Zip shows the adversary transferred and installed a tool onto the target system to facilitate data compression and staging.

---

## 5. Response

### Actions Taken
- Immediately isolated the system upon discovering the archiving activities.

- Created a detection rule to monitor any suspicious activity. Within this alert, the machine will be automatically isolated, serving as a makeshift Data Loss Prevention (DLP) solution.

```kql
DeviceFileEvents
| where FileName endswith ".zip"
| summarize ZipFileActivity = count() by RequestAccountName
| where ZipFileActivity > 5
```
- Relayed the information to the John's manager, including the archived data being created at regular intervals via powershell script. There didn't appear to be any evidence of exfiltration.
---

## 6. Improvement

### Prevention:
- **Principle of Least Privilege and Access Controls**: Limit access based on employees' roles. Review and adjust any unnecessary or elevated access privileges to employees on the PIP program while also avoiding overly restrictive policies to allow the employee to improve performance.
- **Continuous Monitoring**: Deploy Data Loss Prevention (DLP) solutions and implement continuous monitoring to detect and block suspicious behaviours such as silent tool installation, data compression or exfiltration attempts.
- **PowerShell Restrictions**: Place PowerShell into Constrained Language Mode, reducing risk of executing malicious scripts.
- **Real-Time Alerting**: Use EDR and DLP solutions to detect anomalies such as unauthorised archive creation and silent Powershell program installations

### Threat Hunting:
- Use KQL queries to focus on Powershell commands installing tools or compression utilities (7-Zip) and creation of archive files (.zip, .rar)
- Correlate network events between `DeviceFileEvents` and `DeviceProcessEvents` to detect potential exfiltration attempts
- Regularly audit changes to user privileges especially unauthorised privilege escalations

---

## Conclusion

Data exfiltration remains a formidable threat from those that may or may not have appropriate access controls. It is critical to monitor employee behaviour closely through necessary tools and telemetry to mitigate these risks. Though this investigation did not uncover any critical or confirmed external data transfer, the tactics that were used exposed severe security gaps. Addressing these gaps is necessary to strengthen defences against attacks from within.


