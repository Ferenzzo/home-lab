# Lab 05 — Windows File Integrity Monitoring (FIM) with Wazuh

**Date:** November 20, 2026  
**Environment:** Windows 11 host endpoint | Wazuh 4.12.0 | Rocky Linux Wazuh Manager  
**Type:** Authorized home-lab investigation  
**Outcome:** Configured real-time FIM monitoring for `C:\\FIM-Lab` and confirmed file creation, modification (including hash changes), and deletion events in Wazuh Threat Hunting. Also investigated and recovered from a full Manager filesystem.

## Objective

Configure the Wazuh agent on a Windows 11 endpoint to monitor a dedicated test directory in real time and investigate file creation, modification, and deletion events in the Wazuh Dashboard.

This lab demonstrates how a SOC analyst can use File Integrity Monitoring (FIM) to identify changes to files on an endpoint.

## Lab environment

| Component | Details |
|---|---|
| Endpoint | Physical Windows 11 PC |
| Wazuh agent | Wazuh Agent 4.12.0 |
| Agent service | `WazuhSvc` |
| Dashboard agent name | `WinServer-Lab` (label in dashboard; endpoint is Windows 11) |
| Manager | Rocky Linux VM / Wazuh Manager |
| Wazuh Manager version | Wazuh 4.12.0 |
| Test directory | `C:\\FIM-Lab` |

> The dashboard agent name `WinServer-Lab` is a label. The monitored endpoint used in this lab is the user's Windows 11 PC, not a Windows Server installation.

## 1. Verify the Windows Wazuh agent

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
Get-Service WazuhSvc
```

**Purpose:** Confirm the Wazuh agent service is running before configuring FIM.

**Observed result:** The service was running.

## 2. Create a dedicated FIM test directory

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
New-Item -Path "C:\\FIM-Lab" -ItemType Directory
```

Verify:

```powershell
Test-Path "C:\\FIM-Lab"
```

**Purpose:** Create an isolated directory for controlled file monitoring tests.

**Observed result:** The directory was created and the existence check returned `True`.

## 3. Inspect the existing agent configuration

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
Select-String -Path "C:\\Program Files (x86)\\ossec-agent\\ossec.conf" -Pattern "<syscheck>|</syscheck>|<directories"
```

**Purpose:** Locate the existing Syscheck configuration and avoid duplicating or replacing the existing `<syscheck>` section.

**Observed result:** The agent configuration already contained a Syscheck section with existing monitoring entries.

## 4. Configure real-time monitoring for C:\\FIM-Lab

**Location:** Windows 11 host — Notepad opened with elevated privileges.

Open the configuration:

```powershell
notepad "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
```

Inside the existing `<syscheck>` section, add the following entry immediately before its closing `</syscheck>` tag:

```xml
<directories check_all="yes" realtime="yes">C:\\FIM-Lab</directories>
```

Save the configuration.

Verify the saved entry:

**Location:** Windows 11 host — PowerShell (Run as Administrator)

```powershell
Select-String -Path "C:\\Program Files (x86)\\ossec-agent\\ossec.conf" -Pattern "C:\\\\FIM-Lab"
```

**Purpose:** Configure Syscheck to monitor the dedicated directory and its file attributes and hashes, with real-time detection enabled.

**Observed result:** The saved configuration contained the monitoring entry for `C:\\FIM-Lab`.

## 5. Restart and verify the agent

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Restart:

```powershell
Restart-Service WazuhSvc
```

Verify:

```powershell
Get-Service WazuhSvc | Select-Object Name, Status
```

**Purpose:** Reload the agent configuration.

**Observed result:** `WazuhSvc` returned to `Running`.

## 6. Verify FIM initialization in the agent log

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
Get-Content "C:\\Program Files (x86)\\ossec-agent\\ossec.log" -Tail 30
```

Relevant observed messages included:

- `Connected to the server ([208.8.8.128]:1514/tcp)`
- `Agent is now online`
- `File integrity monitoring scan started`
- `File integrity monitoring scan ended`
- `FIM sync module started`
- `Real-time file integrity monitoring started`

A further filtered search confirmed the monitored path and options:

```powershell
Select-String -Path "C:\\Program Files (x86)\\ossec-agent\\ossec.log" -Pattern "syscheck|FIM-Lab|fim-test|file integrity"
```

Observed log entry:

```
Monitoring path: 'c:\\fim-lab', with options 'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | attributes | realtime'.
```

**Conclusion:** The agent loaded the monitoring path and real-time monitoring initialization was confirmed in the log.

## 7. Troubleshooting: Wazuh Manager disk space exhaustion

During the investigation, FIM events initially did not appear in Threat Hunting. The Windows agent was running and the dashboard showed the agent as Active. The Windows agent log also showed that the FIM monitoring path was loaded.

The investigation then revealed that the Rocky Linux Wazuh Manager root filesystem was full.

### 7.1 Check filesystem usage

**Location:** Rocky Linux VM — Terminal

```bash
df -h
```

**Observed result:** The root filesystem was at 100% utilization with approximately 20 KB available.

### 7.2 Identify the disk usage

**Location:** Rocky Linux VM — Terminal

```bash
du -xhd1 / 2>/dev/null | sort -h
```

Then inspect `/var`:

```bash
du -xhd1 /var 2>/dev/null | sort -h
```

Then inspect Wazuh:

```bash
du -xhd1 /var/ossec 2>/dev/null | sort -h
```

Then inspect the queue:

```bash
du -xhd1 /var/ossec/queue 2>/dev/null | sort -h
```

Then inspect the vulnerability detection updater:

```bash
du -xhd1 /var/ossec/queue/vd_updater 2>/dev/null | sort -h
```

**Observed result:** The Wazuh queue and Vulnerability Detection updater temporary directory accounted for the disk usage. The updater's `tmp` directory was approximately 16 GB; the `rocksb` database was much smaller.

### 7.3 Recover space from the updater temporary directory

**Location:** Rocky Linux VM — Terminal (root)

The Wazuh Manager was stopped before clearing the updater's temporary contents.

The temporary directory contents were removed while preserving the directory itself:

```bash
find /var/ossec/queue/vd_updater/tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
```

> This is a destructive cleanup command. It was used in this lab only after identifying the exact directory and stopping the manager. Do not substitute or alter the path casually.

Verify recovered space:

```bash
df -h /
```

**Observed result:** Approximately 16 GB became available and root filesystem utilization fell from 100% to approximately 40%.

### 7.4 Restart Wazuh Manager and verify

**Location:** Rocky Linux VM — Terminal (root)

```bash
systemctl start wazuh-manager
systemctl status wazuh-manager
```

**Observed result:** Wazuh Manager returned to running.

**Location:** Wazuh Dashboard — Agents

**Observed result:** The Windows agent `WinServer-Lab` returned to Active.

> The disk-full condition was discovered during troubleshooting. The lab observed FIM alerts after space was recovered and the manager was restarted, but the sequence alone does not prove disk exhaustion was the sole cause of the earlier missing dashboard results.

## 8. Test file creation detection

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Create a test file:

```powershell
New-Item -Path "C:\\FIM-Lab\\fim-test2.txt" -ItemType File
```

**Purpose:** Generate a controlled file-creation event in the monitored directory.

**Observed result:** The file was created.

**Location:** Wazuh Dashboard — Threat Hunting → Events

Search for the test file using the Syscheck path field, then expand the event.

Observed event:

```
File 'c:\\fim-lab\\fim-test2.txt' added
Mode: realtime
```

The dashboard showed a file-added event with **Rule ID 554**, **Level 5**.

**Conclusion:** Real-time file creation detection was confirmed.

## 9. Test file modification detection

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
Add-Content -Path "C:\\FIM-Lab\\fim-test2.txt" -Value "Second FIM test - modified"
```

**Purpose:** Append content to the file to change its size, modification time, and content hashes.

**Observed result:** The file was modified.

**Location:** Wazuh Dashboard — Threat Hunting → Events

Observed event:

```
File 'c:\\fim-lab\\fim-test2.txt' modified
Mode: realtime
Changed attributes: size,mtime,md5,sha1,sha256
Size changed from '0' to '28'
Old modification time was: '1795182462', now it is '1795182681'
Old md5sum was: 'd41d8cd98f00b204e9800998ecf8427e'
New md5sum is : '1708b1e19fe868ede7a3014ae0cb2a43'
Old sha1sum was: 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
New sha1sum is : 'e29806ab9d89275c31c74de4b5f7c477aed6590f'
Old sha256sum was: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
New sha256sum is : '61be3f4fabc3513268f361b83f299c6285853c5aef9b0f6388709d247894b41a'
```

### Hash comparison

| Hash | Before (empty file) | After modification |
|---|---|---|
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` | `1708b1e19fe868ede7a3014ae0cb2a43` |
| SHA-1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | `e29806ab9d89275c31c74de4b5f7c477aed6590f` |
| SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `61be3f4fabc3513268f361b83f299c6285853c5aef9b0f6388709d247894b41a` |

**Conclusion:** Real-time file modification detection was confirmed. Wazuh reported changes to size, modification time, and content hashes.

## 10. Test file deletion detection

**Location:** Windows 11 host — PowerShell (Run as Administrator)

Command:

```powershell
Remove-Item "C:\\FIM-Lab\\fim-test2.txt"
```

**Purpose:** Delete the lab test file and verify that Wazuh detects the removal.

**Observed result:** The file was deleted.

**Location:** Wazuh Dashboard — Threat Hunting → Events

Observed event:

```
File 'c:\\fim-lab\\fim-test2.txt' deleted
Mode: realtime
```

**Conclusion:** Real-time file deletion detection was confirmed.

## 11. Results

| Test | Observed event | Detection mode | Result |
|---|---|---|---|
| Creation | File added (Rule 554, Level 5) | Realtime | Confirmed |
| Modification | Size, mtime, MD5, SHA-1 and SHA-256 changed | Realtime | Confirmed |
| Deletion | File deleted | Realtime | Confirmed |

## 12. SOC analyst perspective

File Integrity Monitoring helps an analyst identify changes to files on monitored endpoints. An alert is a starting point for investigation—not automatically proof of malicious activity.

For a real investigation, an analyst should consider:

- Which file was changed?
- Which endpoint experienced the change?
- Was the change expected and authorized?
- What changed (metadata, size, permissions, or hashes)?
- Was the activity associated with a known administrative action, software update, or suspicious process?
- Are related alerts or events present before and after the change?

This lab used a controlled test directory and deliberate file operations. The results demonstrate the detection capability; they do not represent a real attack.

## 13. Lessons learned

- Confirm the endpoint agent is running and communicating before troubleshooting detection.
- Verify the monitoring path and options in the agent log.
- Real-time FIM can report file creation, modification, and deletion.
- Hash changes provide useful evidence that file contents changed.
- Investigate infrastructure health—including disk space—when monitoring results are missing.
- Avoid deleting Wazuh queue or database data without identifying the exact path and understanding the impact.
- Alert severity alone is not a verdict; alerts require context and investigation.

## 14. Evidence screenshots to attach

Save screenshots in a dedicated evidence folder in the repository, if desired, and link them from this document:

1. Windows agent configuration showing the `C:\\FIM-Lab` entry.
2. Agent log showing the monitored path and real-time FIM initialization.
3. Dashboard event showing file creation.
4. Dashboard event showing file modification and hash changes.
5. Dashboard event showing file deletion.
6. Disk troubleshooting showing root filesystem space recovered.
7. Wazuh Manager running and Windows agent Active after recovery.

---

**Lab status: Completed.** Real-time FIM detection for file creation, modification, and deletion was demonstrated on the Windows 11 endpoint.
