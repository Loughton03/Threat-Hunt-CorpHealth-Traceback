<img width="657" height="987" alt="image" src="https://github.com/user-attachments/assets/bd911183-b512-4165-b24d-64fd7c8ad53a" />


# Azuki: Bridge Takeover 

## Index

Executive Summary
Technical Analysis
Affected Systems & Data
Evidence Sources & Analysis
Indicators of Compromise (IoCs)
Root Cause Analysis
Technical Timeline
Nature of the Attack
Impact Analysis
Response and Recovery Analysis
Immediate Response Actions
Eradication Measures
Recovery Steps
Post-Incident Actions
Annex A
Technical Timeline
MITRE ATT&CK Technique Mapping

## Executive Summary
- Incident Report: Bridge Takeover & Data Exfiltration
- Incident ID: INC-2025-12-23-AZUKI
- Date: January 30, 2026
- Analyst:
</br>
On November 24, 2025, the Azuki Import/Export network experienced a critical security breach involving lateral movement and data exfiltration. Threat actors utilized a compromised internal host (10.1.0.204) to pivot to a high-value administrative workstation (azuki-adminpc) belonging to the CEO. The attackers leveraged compromised credentials for the user yuki.tanaka to establish a foothold, deploy a Metasploit Meterpreter C2 implant, and create a shadow administrator account for persistence. The primary objective was financial data theft; the attackers aggregated banking records, tax documents, and password databases, exfiltrating them to the public file-sharing service gofile.io.


## Technical Analysis
Affected Systems & Data:

- Target System: `azuki-adminpc` (CEO/Administrative Workstation).
- Compromised Accounts: `yuki.tanaka` (Primary Victim), `yuki.tanaka2` (Backdoor Account).

## Exfiltrated Data:
- Financial Records: Banking, QuickBooks, Tax, and Contract records.
- Credentials: Azuki-Passwords.kdbx (KeePass database), OLD-Passwords.txt (Plaintext), and Google Chrome Login Data.

## Evidence Sources & Analysis
- DeviceLogonEvents: Confirmed lateral movement via RDP from 10.1.0.204 using yuki.tanaka.
- DeviceProcessEvents: Revealed execution of Living-off-the-Land (LOTL) binaries (curl, robocopy, nltest) and malicious tools (m.exe, meterpreter).
- DeviceNetworkEvents: Identified C2 infrastructure (litter.catbox.moe) and exfiltration destinations (store1.gofile.io at IP 45.112.123.227).
- DeviceFileEvents: Tracked the creation of staging directories in C:\ProgramData\Microsoft\Crypto\staging and payload extraction in C:\Windows\Temp\cache.

## Indicators of Compromise (IoCs)
IPv4 Addresses:
- 10.1.0.204 (Internal Lateral Movement Source).
- 45.112.123.227 (Exfiltration Destination - gofile.io).</br>
Domains:
- litter.catbox.moe (Malware Hosting).
- store1.gofile.io (Exfiltration).</br>
Filenames:
- meterpreter.exe (C2 Implant).
- m.exe (Renamed Mimikatz).
- KB5044273-x64.7z (Malicious Payload masquerading as Update).
- Named Pipe: \Device\NamedPipe\msf-pipe-5902.

## Root Cause Analysis
The root cause was the reuse of compromised credentials (yuki.tanaka) from a previously infected workstation, allowing attackers to move laterally via RDP to the administrative workstation. The lack of MFA on internal RDP connections facilitated this pivot.

## Technical Timeline

## Impact Analysis
- Confidentiality (Critical): Loss of sensitive financial data (banking/tax records), master passwords (Azuki-Passwords.kdbx), and browser-stored credentials.
- Integrity (High): System integrity compromised via the creation of backdoor administrative accounts and the modification of system groups.
- Availability (Low): No ransomware or destructive wiping was observed; operations were not halted.

## Response and Recovery Analysis
## Immediate Response Actions

## Eradication Measures
Malware Removal
- Identification: Search for meterpreter.exe, m.exe, and .tar.gz archives in C:\Windows\Temp\cache\ and C:\ProgramData\Microsoft\Crypto\staging.
- Removal Techniques: Delete identified files and remove the yuki.tanaka2 user profile.
- Verification: Verify no active named pipes matching msf-pipe-* exist and that the rogue account is removed from the Administrators group.
System Patching
- Patch Management: Ensure all Windows updates are applied.


## Recovery Steps
Data Restoration
- Backup Validation: Ensure backups of azuki-adminpc prior to Nov 24 are clean.
- Restoration Process: Re-image azuki-adminpc is recommended due to the level of administrative compromise.
- Data Integrity Checks: Validate financial records against bank statements to ensure no tampering occurred during the breach.
System Validation
- Security Measures: Deploy EDR agents with updated rules for curl/robocopy anomalies.
- Operational Checks: Verify user access to necessary shares without using the compromised yuki.tanaka credentials.

## Post-Incident Actions
Monitoring
- Enhanced Monitoring Plans: Alert on curl.exe or tar.exe accessing Login Data or creating files in ProgramData subdirectories.
- Tools and Technologies: Tune EDR to flag Robocopy operations targeting multiple user document folders rapidly.

## Annex A
## Technical Timeline
## MITRE ATT&CK Technique Mapping

























//![image]()


