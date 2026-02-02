<img width="657" height="987" alt="image" src="https://github.com/user-attachments/assets/bd911183-b512-4165-b24d-64fd7c8ad53a" />

## Executive Summary
- Incident Report: Bridge Takeover & Data Exfiltration
- Incident ID: INC-2025-12-23-AZUKI
- Date: January 30, 2026
- Analyst:

## Incident Overview
This report provides a breakdown of the Advanced Persistent Threat (APT) breach detected at Azuki Import/Export in November 2025. The attackers established a foothold on November 19, then paused for three days. They resurfaced on November 22 with an attack geared towards moving laterally across the network and stealing user credentials.

This report documents the complete attack chain through Microsoft Defender for Endpoint telemetry analysis, utilizing Kusto Query Language (KQL) to identify Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) aligned with the MITRE ATT&CK framework.

## INVESTIGATION METHODOLOGY
* Data Sources:
- Microsoft Defender for Endpoint Logs
- DeviceLogonEvents
- DeviceProcessEvents
- DeviceFileEvents
- DeviceRegistryEvents
- Analysis Period: November 19 - 25, 2025

Query Language: Kusto Query Language (KQL)

Framework: MITRE ATT&CK




## MITRE ATT&CK MAPPING

| Tactic           | Technique   | Procedure |
| -------------    |:-----------:| :--------:|
Initial Access	   | T1078	     |  Valid Accounts - Compromised credentials used for RDP access
Lateral Movement   | T1021.001	 |  Remote Desktop Protocol - mstsc.exe to file server
Discovery          | T1135	     |  Network Share Discovery - net.exe enumeration
Discovery	         | T1033	     |  System Owner/User Discovery - whoami.exe execution
Discovery	         | T1016	     |  System Network Configuration - ipconfig.exe execution
Defense Evasion    | T1105	     |  Ingress Tool Transfer - certutil.exe downloads
Defense Evasion    | T1036.003	 |  Masquerading - Renamed credential dumping tools
Collection	       | T1005	     |  Data from Local System - CSV/XLSX file creation
Collection	       | T1074.001	 |  Local Data Staging - robocopy.exe operations
Collection	       | T1560.001	 |  Archive via Utility - 7z.exe compression
Credential Access  | T1003.001	 |  LSASS Memory Dumping - Credential theft
Exfiltration	     | T1041	     |  Exfiltration Over C2 - curl.exe uploads
Exfiltration	     | T1567.002	 |  Cloud Storage Exfiltration - Cloud service uploads
Persistence	       | T1547.001	 |  Registry Run Keys - Autostart mechanism
Defense Evasion    | 	T1070.004	 |  File Deletion - History file removal


## Impact Analysis
- Confidentiality (Critical): Loss of sensitive financial data (banking/tax records), master passwords (Azuki-Passwords.kdbx), and browser-stored credentials.
- Integrity (High): System integrity compromised via the creation of backdoor administrative accounts and the modification of system groups.
- Availability (Low): No ransomware or destructive wiping was observed; operations were not halted.

## Attack Timeline

## Flag 1:
```kql

```

## Flag 2:
```kql

```

## Flag 3:
```kql

```
## Flag 4:
```kql

```

## Flag 5:
```kql

```
## Flag 6:
```kql

```

## Flag 7:
```kql

```

## Flag 8:
```kql

```

## Flag 8:
```kql

```

## Flag 10:
```kql

```

## Flag 11:
```kql

```

## Flag 12:
```kql

```

## Flag 13:
```kql

```

## Flag 14:
```kql

```

## Flag 15:
```kql

```

## Flag 16:
```kql

```

## Flag 17:
```kql

```

## Flag 18:
```kql

```

## Flag 19: 
```kql

```

## Flag 20: 
```kql

```

## Indicators of Compromise (IoCs)
Network Indicators
Attacker Source IP: [Refer to Flag 1 results]
File Server IP: 10.1.0.188
Exfiltration Destination: [Extract from Flag 16/17 command lines]

## COMPROMISED ASSETS
Confirmed Compromised Systems
•	azuki-sl (Initial Access Workstation)
o	Compromise Vector: Still investigating. We need to dig deeper into the logs to find exactly how they got in.
o	Attacker Control: Remote Desktop Access
o	Status: COMPROMISED 
•	azuki-fileserver01 (10.1.0.188)
o	Compromise Vector: They pivoted here from the workstation (azuki-sl) using RDP. 
o	Attacker Control: Fully compromised 
o	Status: CRITICALLY COMPROMISED 
Potentially Compromised Accounts
•	Any user account that logged into the file server (azuki-fileserver01) during the attack window should be considered compromised.
•	Service accounts usually have high privileges, so if they touched these infected machines, we have to assume the attackers have those keys now too.



File System Indicators
Renamed Credential Tool: [Flag 14 - FileName and SHA256]
Persistence Beacon: [Flag 19 - Registry Value Data path]
Compressed Archives: [Flag 13 - Identify .7z/.zip file names]
Staged Data Directory: [Flag 12 - robocopy destination path]

Registry Indicators
Persistence Key: HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Persistence Value Name: [Flag 18 result]

Process Execution
mstsc.exe with specific command line parameters
net.exe/net1.exe for share enumeration
whoami.exe for privilege checking
certutil.exe for file downloads
7z.exe for data compression
curl.exe/powershell.exe for exfiltration
Renamed executables targeting LSASS


## Technical Analysis
Affected Systems & Data:

- Target System: `azuki-adminpc` (CEO/Administrative Workstation).
- Compromised Accounts: `yuki.tanaka` (Primary Victim), `yuki.tanaka2` (Backdoor Account).

## Exfiltrated Data:
- Financial Records: Banking, QuickBooks, Tax, and Contract records.
- Credentials: Azuki-Passwords.kdbx (KeePass database), OLD-Passwords.txt (Plaintext), and Google Chrome Login Data.

## Key Evidence Requiring Deeper Analysis

## Lessons Learned

## Threat Actor Assessment
