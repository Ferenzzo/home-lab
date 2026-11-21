# Lab 05 — PowerShell Detection

**Date:** November 21, 2026  
**Environment:** Rocky Linux (Wazuh Manager 4.12.0) / Windows 11 Endpoint  
**Type:** Security Monitoring / Windows Event Logging / SIEM  
**Outcome:** PowerShell logging configured and locally verified; event visibility in Wazuh remains unconfirmed.

## Objective

Configure Windows PowerShell Script Block Logging and forward PowerShell Operational logs to Wazuh to familiarize myself with monitoring PowerShell activity through a SIEM.

## Environment

- **SIEM:** Wazuh
- **Wazuh Manager:** Rocky Linux VM
- **Endpoint:** Windows 11
- **Log Source:** Microsoft-Windows-PowerShell/Operational
- **Event ID:** 4104 — Script Block Logging

## Activities Performed

### 1. Verified Wazuh Services

Checked that the Wazuh Manager and Windows Agent services were running.

- Wazuh Manager: Active
- Wazuh Agent: Running

### 2. Enabled PowerShell Script Block Logging

Configured the Windows Registry to enable PowerShell Script Block Logging.

Registry path:

`HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging`

Configured value:

- **Name:** EnableScriptBlockLogging
- **Type:** DWORD
- **Value:** 1

Verified the registry configuration.

### 3. Verified PowerShell Operational Logging

Checked the Microsoft-Windows-PowerShell/Operational event log and confirmed that it was enabled.

Observed Event ID 4104 records generated locally, including PowerShell configuration commands.

### 4. Configured Wazuh Event Collection

Modified the Wazuh Windows Agent configuration file:

`C:\\Program Files (x86)\\ossec-agent\\ossec.conf`

Added the following configuration:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Created a backup of the original configuration file before making changes.

Restarted the Wazuh Agent service after modifying the configuration.

### 5. Verified Agent Connectivity

Reviewed the Windows Agent logs and confirmed that the agent successfully connected to the Wazuh Manager.

Observed log entries indicating:

- PowerShell Operational event log analysis
- Successful connection to the Wazuh Manager
- Agent online status

### 6. Conducted PowerShell Testing

Executed harmless PowerShell commands and a test script to generate activity.

Observed locally generated Event ID 4104 records in the PowerShell Operational event log.

### 7. Investigated SIEM Visibility

Attempted to locate Event ID 4104 records in the Wazuh Threat Hunting dashboard.

Although PowerShell logging was enabled and the agent was configured to collect the PowerShell Operational channel, the corresponding events were not successfully confirmed in the dashboard during this lab.

## Findings

- PowerShell Script Block Logging was enabled through the Windows Registry.
- Event ID 4104 was observed locally in Windows Event Viewer.
- The Wazuh Windows Agent was configured to collect PowerShell Operational logs.
- Wazuh Agent connectivity was verified.
- Event visibility within the Wazuh dashboard was not confirmed.

## Learning Outcome

This lab provided hands-on exposure to Windows PowerShell logging, Windows Registry policy configuration, event log collection, Wazuh agent configuration, and SIEM troubleshooting.

I learned that generating security events on an endpoint does not automatically guarantee that the events are visible within the SIEM. Log collection, forwarding, and dashboard visibility must also be verified.

**Status:** Configuration and local event generation verified; SIEM event visibility requires further investigation.
