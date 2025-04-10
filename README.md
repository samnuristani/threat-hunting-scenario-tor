<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/samnuristani/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvent table for any file that had the string "tor" in it and discovered what looks like the user `winonboarding` downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `03:04:57 PM` on '2025-04-3'. Other went were subsequently created.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "windows-vm-sam"  
| where FileName contains "tor"  
| where Timestamp >= ago(30d)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, InitiatingProcessFolderPath
| sort by Timestamp desc;
```
![kql q1 result](https://github.com/user-attachments/assets/a02b515a-831d-41c4-8da7-2c1fe9ce315f)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.9.exe". Based on the logs returned, at 03:15:13 PM, April 3, 2025, the `winonboarding` user on the `windows-vm-sam` device ran the file `tor-browser-windows-x86_64-portable-14.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "windows-vm-sam"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"  
| project Timestamp, DeviceName, ActionType, FileName, SHA256, FolderPath, FileSize, ProcessCommandLine, AccountName
| order by Timestamp desc;
```
![kql q2 result](https://github.com/user-attachments/assets/e1f51820-f090-46a7-a2d3-5d58b6b0b1ff)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user `winonboarding` on `windows-vm-sam` device actually opened the TOR browser. There was evidence that they did open it at `2025-04-03T22:15:56.4176451Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![kql q3 result](https://github.com/user-attachments/assets/e742188f-9a9f-4f3c-9fe0-8492bfbd40aa)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-03T22:16:04.3061798Z`, the `winonboarding` user on the `windows-vm-sam` device successfully established a connection to the remote IP address `107.189.6.124` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\winonboarding\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
// Define target ports (Tor + Web)
let suspiciousPorts = dynamic([9001, 9030, 9040, 9051, 9150, 80, 443]);
DeviceNetworkEvents
| where DeviceName == "windows-vm-sam"
| where tolower(InitiatingProcessFileName) in~ ("tor.exe", "firefox.exe") // Case-insensitive match
| where tolower(InitiatingProcessAccountName) !in~ ("system", "network service", "local service") // Exclude system accounts
| where RemotePort in (suspiciousPorts) // filtering by port numbers
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc;
```
![kql q4 result](https://github.com/user-attachments/assets/fd591c1f-3cd3-493f-b5a0-f6b56875a2ac)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-03T22:15:13Z`
- **Event:** The user `windonboarding` downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\users\winonboarding\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-03T22:15:13.720072Z`
- **Event:** The user `windonboarding` executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe  /S`
- **File Path:** `C:\Users\winonboarding\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-03T22:15:56.4176451Z`
- **Event:** User `windonboarding` opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\winonboarding\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-03T22:16:04.3061798Z`
- **Event:** A network connection to IP `107.189.6.124` on port `443` by user `windonboarding` was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\winonboarding\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-03T22:16:11.1348304Z` - Connected to `46.167.244.238` on port `443`.
  - `2025-04-03T23:05:42.7919759Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user `windonboarding` through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `22025-04-03T22:50:34.9116165Z`
- **Event:** The user `winonboarding` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\winonboarding\Desktop\tor-shopping-list.txt`

---

## Summary

The user `winonboarding` on the `windows-vm-sam` device initiated and completed the installation of the Tor browser. They proceeded to launch the Tor browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file. 

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-vm-sam` by the user `winonboarding`. The device was isolated, and the user's direct manager was notified.

---
