# Execution-and-Lateral-Movement-Detection-TryHackMe-SOC-Simulation-
The scenario below is only a simulation and does not contain any real company or individual data. The simulation is provided by TryHackMe.com meant for educational training purposes of real-world incidents.

**Author:** Blake Anderson  
**Platform:** TryHackMe.com  
**Tools Used:** Splunk, Sysmon, MITRE ATT&CK Framework  

---

## Scenario Overview
This simulation replicates a **process execution and potential lateral movement detection** within a Windows environment monitored by Splunk.  
The alert flagged suspicious behavior involving `net.exe` executing from a **non-standard directory** under a **non-privileged user account** (`michael.ascot`), prompting immediate investigation.

---

## Alert Summary

- **Alert Type:** Suspicious Process Execution  
- **Process Name:** `net.exe`  
- **Parent Process:** `powershell.exe`  
- **Host:** `WIN-3450`  
- **Working Directory:** `C:\Users\michael.ascot\Downloads`  
- **Timestamp:** `2025-10-02T19:14:17Z`  

---

## Investigation Steps

1. **Initial Analysis (Splunk SIEM)**
   - Queried Sysmon logs for Process Create events:
     ```splunk
     datasource=sysmon "event.action"="Process Create (rule: ProcessCreate)" "process.name"="net.exe" "process.working_directory"="C:\\Users\\michael.ascot\\Downloads\\"
     ```
   - Observed multiple executions of `net.exe` initiated from within PowerShell — an unusual and potentially malicious context.

2. **Event Correlation**
   - Identified two distinct commands:
     ```
     net use Z: \\FILESRV-01\SSF-FinancialRecords
     net use Z: /delete
     ```
   - Both commands occurred within **one minute**, indicating possible **temporary network drive mapping** to exfiltrate or stage files.

3. **Timeline Reconstruction**
   - Found an earlier event (same process and parent) executed from the same directory prior to the latest alerts.  
   - Determined a consistent behavioral pattern of **short-lived network mapping**.

4. **Tactics and Techniques Mapping**
   - Referenced **MITRE ATT&CK** to align observed behavior with:
     - **T1021.002 – Remote Services: SMB/Windows Admin Shares**  
     - **T1077 – Windows Admin Shares**  
     - **T1086 – PowerShell Execution**  
     - **T1105 – Ingress Tool Transfer**  
   - Concluded the activity matched **Lateral Movement / Staging Behavior** leveraging **LOLBins** (`net.exe`, `powershell.exe`).

---

## Findings

- **IOC:** Repeated short-lived `net.exe` executions via PowerShell  
- **Behavioral Indicators:**
  - Execution from user’s Downloads directory (non-standard path)
  - Rapid mapping/unmapping of SMB shares
  - Scripted PowerShell parent process
- **Assessment:** True Positive (Likely malicious activity)
- **Potential Objective:** Staging or file transfer prior to lateral movement

---

## Actions Taken

- Documented event details, timestamps, and Splunk query results in the incident ticket.  
- Classified alert as a **True Positive**.  
- **Escalated** to Tier 2 / Incident Response for:
  - File server log review (`\\FILESRV-01\SSF-FinancialRecords`)
  - Memory capture and forensic examination
  - Endpoint Detection & Response (EDR) deep-dive analysis  
- Recommended follow-up actions:
  - Audit network shares for unauthorized access
  - Verify user permissions
  - Review PowerShell execution logs and Group Policy restrictions

---

## Outcome

Investigation confirmed abnormal process behavior consistent with **Lateral Movement** preparation using legitimate system binaries (LOLBins).  
The alert was escalated for deeper forensic review, with recommendations to strengthen **PowerShell script controls**, **network share auditing**, and **EDR monitoring**.

---

## Skills Demonstrated

- Splunk log analysis using Sysmon data  
- Detection of LOLBAS (Living-off-the-Land Binary) activity  
- MITRE ATT&CK technique mapping  
- Lateral movement detection and escalation  
- SOC documentation and response procedures  

---

## Screenshots

<img width="628" height="301" alt="image" src="https://github.com/user-attachments/assets/d617e92b-493a-4589-bb1b-2ca06bd59671" />
<img width="634" height="283" alt="image" src="https://github.com/user-attachments/assets/d0352fec-d0c9-4421-8d57-e058d28ddb42" />
<img width="633" height="237" alt="image" src="https://github.com/user-attachments/assets/a2e1db13-1de0-48dd-b8d9-6ba0913d7fe9" />
<img width="635" height="227" alt="image" src="https://github.com/user-attachments/assets/fb908c5c-a9f5-496d-a546-472299ceb52f" />
