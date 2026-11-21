# Lab 06 — PowerShell Detection

**Date:** November 21, 2026  
**Environment:** Rocky Linux VM (Wazuh Manager) / Windows 11 Endpoint  
**Type:** Security Monitoring / Windows Event Logging / SIEM  
**Outcome:** Script Block Logging and agent collection configured; local event generation and agent connectivity verified, but Event ID 4104 visibility in the Wazuh dashboard was not confirmed.

## Objective

Enable PowerShell Script Block Logging on Windows, configure the Wazuh agent to collect the PowerShell Operational log, generate harmless test activity, and investigate whether the events are visible in Wazuh.

## Tools Used

- Wazuh Dashboard
- Wazuh Manager (Rocky Linux)
- Windows PowerShell
- Windows Registry
- Windows Event Viewer / PowerShell Operational event log

## Step-by-Step Procedure and Commands

### 1. Verify the Wazuh Services

**On Windows PowerShell (Run as Administrator):**

```powershell
Get-Service WazuhSvc
```

This checks the Windows Wazuh agent service status. The service was observed running.

**On the Rocky Linux VM:**

```bash
sudo systemctl status wazuh-manager
```

This checks the Wazuh Manager service. The manager was observed active (running).

### 2. Enable PowerShell Script Block Logging

**On Windows PowerShell (Run as Administrator):**

Create the policy registry key if it does not already exist:

```powershell
New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force
```

Enable Script Block Logging:

```powershell
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force
```

Verify the configured value:

```powershell
Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
```

The **EnableScriptBlockLogging** DWORD was verified with a value of **1**.

### 3. Check the PowerShell Operational Log

**On Windows PowerShell:**

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" | Select-Object LogName, IsEnabled, RecordCount
```

This checks whether the PowerShell Operational event log is enabled and reports its record count. The log was observed enabled.

To inspect recent Event ID 4104 records:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 10 | Format-List TimeCreated, Id, Message
```

Event ID 4104 records were observed locally, including script blocks associated with configuration and verification commands.

### 4. Back Up and Configure the Wazuh Agent

**On Windows PowerShell (Run as Administrator):**

The agent configuration file was located at:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

Create a backup:

```powershell
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec.conf.bak"
```

Check whether a PowerShell Operational channel entry already exists:

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "PowerShell/Operational"
```

No existing PowerShell Operational entry was found during the check.

Open the configuration file for editing:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Inside the existing `<ossec_config>` section, add the following configuration:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Save the file.

### 5. Restart and Verify the Wazuh Agent

**On Windows PowerShell (Run as Administrator):**

```powershell
Restart-Service WazuhSvc
```

Verify the service:

```powershell
Get-Service WazuhSvc
```

The agent service was observed running after the restart.

### 6. Generate Harmless PowerShell Test Activity

**On Windows PowerShell:**

Run a simple test command:

```powershell
Write-Output "SOC-LAB-POWERSHELL-TEST"
```

A test script was also created in the user's temporary directory:

```powershell
Set-Content -Path "$env:TEMP\SOC-Lab-Test.ps1" -Value 'Write-Output "SOC-LAB-4104-TEST"'
```

Execution policy was temporarily bypassed for the current PowerShell process only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The test script was executed:

```powershell
& "$env:TEMP\SOC-Lab-Test.ps1"
```

The script printed its test string in the PowerShell session. This was a harmless test of script execution; the exact test string was not confirmed in the local Event ID 4104 results.

### 7. Inspect Recent PowerShell Script Block Events

**On Windows PowerShell:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 | Format-List TimeCreated, Id, Message
```

The returned records included Script Block Logging activity, such as commands used during configuration and verification. The specific test string was not confirmed in the event output.

### 8. Verify Agent Connectivity and Collection Activity

The Windows Wazuh agent log was reviewed for connection and collection messages.

**On Windows PowerShell:**

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.log" -Pattern "PowerShell/Operational|Connected to the server|Agent is now online|Unable to connect"
```

Earlier connection failures were present in the log, but later entries showed:

- Analyzing the PowerShell Operational event log
- Connected to the Wazuh Manager
- Agent online status

The later entries indicated that the agent was connected and processing the configured event log.

### 9. Investigate Event Visibility in Wazuh

In the Wazuh Dashboard, open Threat Hunting / Discover and search for Windows Event ID 4104 using the field:

`data.win.system.eventID:4104`

The dashboard was checked with a recent time range (60 minutes). The search did not return the expected 4104 events during this lab.

## Findings

- PowerShell Script Block Logging was enabled through the Registry.
- The PowerShell Operational log was enabled.
- Local Event ID 4104 records were observed.
- Wazuh agent configuration was updated to collect the PowerShell Operational channel.
- The Wazuh agent service was restarted and verified running.
- Agent connectivity and analysis of the PowerShell Operational channel were observed in the agent log.
- Event ID 4104 visibility in the Wazuh dashboard was not confirmed.

## Troubleshooting Notes

- Earlier agent log entries showed connection errors to the manager, but later log entries showed a successful connection and the agent online.
- The dashboard search for `data.win.system.eventID:4104` did not return results.
- Local 4104 records were inspected, but the specific test string was not confirmed.
- Troubleshooting was stopped without claiming successful SIEM ingestion of the test event.

## Learning Outcome

This lab provided practice with Windows Registry policy configuration, PowerShell Script Block Logging, Windows Event ID 4104, Wazuh agent configuration, event-channel collection, agent connectivity checks, and SIEM investigation.

**Status:** PowerShell logging and Wazuh collection configuration were completed and locally/agent-side verified. Dashboard visibility of the test events remains unconfirmed.
