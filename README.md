# Threat-Hunting---Sudden-Network-Slowdowns

## Scenario

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the `10.0.0.0/16` subnet. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or conducting a port scan against hosts in the local network.

---

## Investigation

### 1. Searched `DeviceNetworkEvents` for failed connections involving our VM

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by RemoteIP, LocalIP, ActionType, RemoteUrl
| order by ConnectionCount
```

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/4707d151-be06-48c3-923c-a1e616e4dd06">


Finding: Observed the machine making several failed connection attempts against itself, another host on the same network, and several Microsoft services.

### 2. Searched DeviceNetworkEvents for failed connections from our IP address


```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| where LocalIP == "10.0.0.5"
| order by Timestamp asc
```

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/bac8bb58-7fa3-48ea-8176-a64457100b29">


Finding: After observing the connection failures from IP address 10.0.0.5 in chronological order, I determined a port scan was taking place due to the sequential order of the ports.

### 3. Attempted to locate process events around the earliest seen time for connection failures

```kql
let specifictime = datetime(2025-04-15T08:38:23.5319143Z);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where Timestamp between ((specifictime +1h) .. (specifictime -1h))
```
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/8b8100ce-25e9-43ed-a055-16352fa577d0">



Finding: There were no results. I believe the port scan was initially launched at an earlier date, which is outside of the current log retention settings of 30 days. Regardless, a port scan under these conditions is not expected behavior.

### 4. Re-ran the earlier connection failure query to inspect expanded results

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| where LocalIP == "10.0.0.5"
| order by Timestamp asc
```

Finding: I noticed there was a PowerShell script running a port scan.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/7a88f519-15c7-4b80-8fb4-11be25c31690">


### 5. Checked file events related to portscan.ps1

```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp asc
```
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/957d0735-b226-4319-90d8-a7139e638106">


Finding: An expanded result showed that portscan.ps1 was initiated by the SYSTEM account with a -ExecutionPolicy Bypass flag, meant to circumvent PowerShell’s script execution restrictions.

## Response

I isolated the device and ran a malware scan. The scan produced no results. However, out of an abundance of caution, I submitted a ticket to have the machine rebuilt.

## MITRE ATT&CK TTPs

| Technique ID | Name                               | Tactic               |
|--------------|------------------------------------|----------------------|
| T1046        | Network Service Scanning           | Reconnaissance       |
| T1059        | Command and Scripting Interpreter  | Execution            |
| T1078.003    | Valid Accounts: Local Accounts     | Privilege Escalation |

---
Analyst Contact

Name: Britt Parks

Contact: [linkedin.com/in/brittaparks](https://www.linkedin.com/in/brittaparks)


Date: May 15, 2025
