# Lab 04 — Windows Authentication Event Investigation with Wazuh

**Date:** November 20, 2026  
**Environment:** Windows 11 host endpoint | Wazuh 4.12.0 | Rocky Linux Wazuh Manager  
**Type:** Authorized home-lab investigation  
**Outcome:** Located and examined Windows failed-logon (4625), privileged-logon, and successful service-logon events in Wazuh Threat Hunting.

## Objective

Practice SOC-style event triage using Wazuh: locate a failed logon, inspect the underlying Windows event fields, review surrounding authentication/privilege activity, and make cautious preliminary classifications based on evidence.

## Lab environment

| Component | Role | Details |
|---|---|---|
| Rocky Linux VM (WAZUHv2) | Wazuh Manager | Manager service verified active |
| Wazuh Manager address | Agent destination | `208.8.8.128` (observed during lab; DHCP address may change) |
| Windows 11 host PC | Monitored endpoint | Existing Wazuh Agent connection |
| Agent name in dashboard | Endpoint label | `WinServer-Lab` (label is misleading; endpoint is the real Windows 11 host) |
| Agent version | Endpoint agent | Wazuh 4.12.0 |

> The endpoint investigated was the user's real Windows 11 PC, not the Windows Server VM. The Windows Server VM did not have a Wazuh agent installed during this exercise.

## Procedure

1. Verified that the Wazuh Manager service was `active (running)` on Rocky Linux.
2. Confirmed the manager address with `hostname -I`: `208.8.8.128`.
3. Used the existing monitored Windows 11 endpoint.
4. Locked the PC and performed one intentional incorrect-password attempt, then logged in successfully.
5. Opened Wazuh Threat Hunting → Events.
6. Searched for Windows Event ID 4625 using:

```
data.win.system.eventID:4625
```

7. Located failed-logon alerts and inspected the most recent available event details.
8. Reviewed other events in a narrowed time window, including a special-privileges event and a successful service-logon event.

## Failed-logon event analysis — Event ID 4625

Wazuh displayed a failed-logon alert (Rule ID 60122, Level 5) with the description **Logon Failure – Unknown user or bad password**.

Observed raw event fields:

| Field | Value |
|---|---|
| Event ID | 4625 |
| Subject SID | `S-1-5-18` |
| Subject account | `DEOCESCO$` |
| Subject domain | `WORKGROUP` |
| Subject logon ID | `0x3E7` |
| Logon Type | `2` |
| Failed target account | `-` |
| Failed target SID | `S-1-0-0` |
| Failure reason | An error occurred during logon |
| Status | `0xC000006D` |
| SubStatus | `0xC0000380` |
| Caller process ID | `0x91c` |
| Caller process | `C:\Windows\System32\svchost.exe` |
| Source address | `127.0.0.1` |
| Source port | `0` |
| Logon process | `User32` |
| Authentication package | `Negotiate` |

### Interpretation

- Event ID 4625 confirms that a logon attempt failed.
- Logon Type 2 is an interactive logon type.
- The source address `127.0.0.1` is the loopback address and indicates a local context, not an external IP address.
- The failed target account fields were blank/unknown in this record.
- `svchost.exe` is a legitimate Windows executable, but its presence alone does not prove an event is benign.
- Status `0xC000006D` is a logon-failure status. The SubStatus was recorded as `0xC0000380`; its precise interpretation was not independently verified in this exercise.

### Preliminary classification

**Likely benign / consistent with local test activity, but not conclusively correlated.** The event's local loopback context and the lab activity make it plausible that it was related to the test. However, the event did not identify the failed target account, and the details alone do not conclusively prove that this exact event was caused by the intentionally entered incorrect password.

## Additional event reviewed — Special privileges assigned to new logon

Observed details:

| Field | Value |
|---|---|
| Account | `deocescoferenzzo.ramos@gmail.com` |
| Domain | `MicrosoftAccount` |
| Logon ID | `0xDAD3DB` |
| Event description | Special privileges assigned to new logon |

Privileges listed in the event:

- `SeSecurityPrivilege`
- `SeTakeOwnershipPrivilege`
- `SeLoadDriverPrivilege`
- `SeBackupPrivilege`
- `SeRestorePrivilege`
- `SeDebugPrivilege`
- `SeSystemEnvironmentPrivilege`
- `SeImpersonatePrivilege`
- `SeDelegateSessionUserImpersonatePrivilege`

These privileges are sensitive and can be abused in some circumstances, but their presence in an event is not proof of misuse. This event's Logon ID differed from the 4625 event's subject Logon ID, so a direct session correlation was not established.

**Preliminary classification:** Likely benign administrative logon context, pending further verification if this were a real incident.

## Additional event reviewed — Successful service logon

Observed event details:

| Field | Value |
|---|---|
| New logon account | `SYSTEM` |
| Domain | `NT AUTHORITY` |
| SID | `S-1-5-18` |
| Logon ID | `0x3E7` |
| Logon Type | `5` (Service) |
| Elevated token | Yes |
| Process | `C:\Windows\System32\services.exe` |
| Process ID | `0x4b0` |
| Logon process | `Advapi` |
| Authentication package | `Negotiate` |

### Interpretation

Logon Type 5 is a service logon. `NT AUTHORITY\SYSTEM` is a built-in Windows system identity, and `services.exe` is the Service Control Manager executable. These fields are consistent with normal Windows service activity. This event alone does not indicate malicious behavior.

**Preliminary classification:** Likely benign service activity.

## SOC analyst assessment

| Event | Evidence | Preliminary disposition |
|---|---|---|
| 4625 — Failed logon | Type 2, loopback `127.0.0.1`, unknown target, `svchost.exe` | Likely benign / consistent with test context; exact causation not proven |
| Special privileges event | MicrosoftAccount and sensitive privileges listed | Likely benign context; direct correlation to 4625 not established |
| Successful service logon | Type 5, SYSTEM, `services.exe` | Likely benign service activity |

A severity level or alert title is not a verdict. In a real investigation, I would validate the asset and account, correlate events by time and logon ID where appropriate, review process context and frequency, look for repeated failures or a subsequent successful logon, and escalate if evidence indicates unauthorized activity.

## Skills practiced

- Wazuh Threat Hunting and event filtering
- Windows Security Event ID 4625 analysis
- Reviewing raw Windows event fields
- Understanding interactive (Type 2) and service (Type 5) logons
- Interpreting local loopback context
- Reviewing Windows privileged-logon events
- Preliminary SOC classification and evidence-based reasoning
- Distinguishing an alert from confirmed malicious activity

## Key takeaway

**Investigate the event details, not just the alert title.** Context, correlation, account identity, logon type, process, source address, and surrounding events are needed to assess whether activity is expected, suspicious, or requires further investigation.

---

*Personal hands-on home-lab exercise. This documents simulated/controlled learning activity, not professional SOC employment.*
