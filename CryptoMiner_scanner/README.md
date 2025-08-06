# Full Anti-Miner Kit v2 + Chrome Process Scanner
Author: Ox1C

---

## Description.

This repository contains two advanced PowerShell scripts designed to help the user to:

- Detect and remove any hidden or persistent crypto-miners in the Windows system
- Analyze and monitor Google Chrome processes in real time for suspicious activity (miners running through the browser)

---

## Content

- `full_anti_miner_kit_v2.ps1` 
 Complete script that performs a thorough system scan:

  - Checks and cleans Run and RunOnce registry keys.
  - Analyzes and removes suspicious Scheduled Tasks
  - Scans and disables suspicious system services
  - Scans TEMP and AppData folders for potentially malicious files
  - Checks for manipulation of shortcuts (.lnk) in Chrome
  - Detailed logs and CSV reports generated on the Desktop

- `chrome_process_scanner.ps1` 
 Lightweight, self-contained script that scans all active chrome.exe processes:

  - Prints for each process: PID, RAM used, full command line
  - Highlights any suspicious flags (--headless, --disable-gpu, etc.).
  - Highlights any keywords that can be traced back to mining
  - Allows quick analysis of anomalous activity via Chrome

---

## Target operating system

- Windows 10
- Windows 11

Requires PowerShell version 5 or higher.

---

## How to use the scripts.

1. Clone the repository or download the individual `.ps1` files.

2. Start PowerShell as Administrator.

3. Run the following commands to allow temporary execution of scripts:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

```
4. Execute the desired script:

To execute the full kit:

.\full_anti_miner_kit_v2.ps1

To run only the Chrome process scanner:

```powershell
.\chrome_process_scanner.ps1
```
Notes
The scripts do not require external modules: everything is integrated and in plain text.

Logs and CSV reports are automatically saved to the user's Desktop.

The scripts are designed for manual, self-aware use: no intrusive automatisms are applied without the user being able to view them (except for automatic removal of clearly suspicious services and tasks).

The list of suspicious keywords and flags is editable within the scripts: it can be customized and updated.

Author
```powershell
Ox1C
```
