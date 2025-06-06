
# Sudden Network Slowdowns

## Overview

The project illustrates a threat hunting investigation focused on a potential unauthorised data exfiltration attempt by a threat from within the organisation. After ruling out external threats, the investigation shifted focus to potentially compromised insiders — those who may have fallen victim to social engineering, credential theft, or malware infection — as well as disgruntled employees motivated by revenge. The primary tool used was **Microsoft Defender for Endpoint (MDE)**, while leveraging Kusto Query Language (KQL) to query detailed threat hunting logs to identify indicators of unauthorised data exfiltration. The findings showcase the importance of continuous monitoring and proactive threat hunting to mitigate insider risks and safeguard sensitive organizational data.


---

## 1. Preparation

### Scenario:

The networking team have noticed a significant decrease in network speed that is mainly affecting the older systems attached to the 10.0.0.0/16 network. This has caused significant slowdown and overall negative performance on the network. DDOS attacks have been ruled out and network engineers are considering that the problem may lie within the endpoints themselves. 

Currently, the traffic originating from the local area network (LAN) is allowed by all endpoints. Applications such as Powershell and others can be used freely by those in the working environment. There are suspicions that a user(s) may be downloading extremely large files or conducting port scans on the internal network. 

### Hypothesis:

John is an administrator on his corporate device with unrestricted access to applications. After his recent placement in the Performance Improvement Plan (PIP), he may try to archive/compress sensitive information and transfer it to an external location for exfiltration.

## 2. Data Collection
  
### Action:
Searched the following Microsoft Defender for Endpoint tables:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

#### Initial Findings:

We did a search within MDE DeviceFileEvents for any activities with zip files, and found a lot of normal activity of archiving files and moving them to a "backup" folder.

```kql
DeviceFileEvents
| where DeviceName == "win-vm-mde"
| where FileName endswith ".zip"
| order by Timestamp desc
```
<img width="1298" alt="Pasted image 20250329155117" src="https://github.com/user-attachments/assets/63e551f6-3f95-4a13-9797-5c5d8224e77a" />

---

## 3. Data Analysis

### Findings

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time that a powershell script silently installed 7zip and then used 7zip to zip up employee data into an archive: 


```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-03-29T07:17:11.3510997Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

<img width="1376" alt="Pasted image 20250329161935" src="https://github.com/user-attachments/assets/39b2327f-4ec6-4949-9741-aceec3d52670" />


### Exfiltration Check

I searched around the same time period for any evidence of exfiltration querying `DeviceNetworkEvents`. There were a few successful connections based on the ActionTypes that were labelled ConnectionSuccess, but none of them contained any signs of external data transfer.

```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-03-29T07:17:11.3510997Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType
```

---

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


