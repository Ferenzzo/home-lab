# Lab 04 — Windows Authentication Event Investigation with Wazuh

**Date:** November 20, 2026  
**Environment:** Windows 11 host endpoint | Wazuh 4.12.0 | Rocky Linux Wazuh Manager  
**Type:** Authorized home-lab investigation  
**Outcome:** Located and examined a failed-logon (4625) event, a special-privileges event, and a successful service-logon event in Wazuh Threat Hunting.

## Objective

Practice SOC-style event triage using Wazuh: locate a failed logon, inspect the underlying Windows event fields, review surrounding authentication and privilege activity, and make cautious preliminary classifications based on evidence.

## Lab environment

| Component | Role | Details |
|---|---|---|
| Rocky Linux VM (WAZUHv2) | Wazuh Manager | Manager service verified active |
| Wazuh Manager address | Agent destination | `208.8.8.128` (observed during lab; DHCP address may change) |
| Windows 11 host PC | Monitored endpoint | Existing Wazuh Agent connection |
| Agent name in dashboard | Endpoint label | `WinServer-Lab` (label is misleading; endpoint is the real Windows 11 host) |
| Agent version | Endpoint agent | Wazuh 4.12.0 |

> The endpoint investigated was the user's real Windows 11 PC, not the Windows Server VM. The Windows Server VM did not have a Wazuh agent installed during this exercise.

## Procedure — Step by step

### Step 1 — Verify the Wazuh Manager

**Location:** WAZUHv2 — Rocky Linux VM terminal

Command used:

```bash
sudo systemctl status wazuh-manager
```

**Purpose:** Check the service status of the Wazuh Manager before beginning the investigation.

**Observed result:** The service was reported as `active (running)`.

### Step 2 — Confirm the Manager IP address

**Location:** WAZUHv2 — Rocky Linux VM terminal

Command used:

```bash
hostname -I
```

**Purpose:** Display the IP address(es) assigned to the Rocky Linux VM so the manager address could be confirmed.

**Observed result:** The address used during this lab was `208.8.8.128`. The address may change if the VM receives a different DHCP lease.

### Step 3 — Generate controlled failed-login activity

**Location:** My PC — Windows 11 host (physical keyboard / lock screen)

1. Locked the Windows 11 PC using `Win + L`.
2. Entered an intentionally incorrect password once.
3. Entered the correct password to regain access to the PC.

**Purpose:** Generate a controlled authentication-failure event for investigation on the endpoint I own and administer.

> This was a controlled test. The investigation did not involve another person's device or account.

### Step 4 — Open Wazuh Threat Hunting

**Location:** My PC — Web browser — Wazuh Dashboard

1. Opened the Wazuh Dashboard.
2. Navigated to **Threat Hunting** / **Events**.
3. Reviewed the events being reported by the monitored endpoint.

**Purpose:** Use the central monitoring dashboard to review security events collected by Wazuh.

### Step 5 — Filter for Windows Event ID 4625

**Location:** My PC — Web browser — Wazuh Dashboard — Events search/filter

Used the event field filter:

```
data.win.system.eventID:4625
```

**Purpose:** Narrow the event list to Windows failed-logon records (Event ID 4625).

**Observed result:** Two matching events were visible in the search results. One was dated November 20, 2026, around 19:00 local dashboard time; another older event was also present. The more recent event was selected for closer review.

### Step 6 — Expand and inspect the raw event

**Location:** My PC — Web browser — Wazuh Dashboard — selected 4625 event

Expanded the selected event to inspect its raw Windows event fields and details.

**Purpose:** Review the evidence behind the alert instead of relying only on its title or severity.

## Failed-logon event analysis — Event ID 4625

Wazuh displayed a failed-logon alert (Rule ID 60122, Level 5) with the description **Logon Failure – Unknown user or bad password**.

Observed raw event fields:

| Field | Value |
|---|---|
| Event ID | 4625 |
| Event Record ID | 63321 |
| Computer | DEOCESCO |
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
| Caller process ID | `0x91c` (decimal 2332) |
| Caller process | `C:\Windows\System32\svchost.exe` |
| Source address | `127.0.0.1` |
| Source port | `0` |
| Logon process | `User32` |
| Authentication package | `Negotiate` |
| Event system time | `2026-11-20T11:00:42.4258446Z` |

### Interpretation

- Event ID 4625 confirms that a logon attempt failed.
- Logon Type 2 is an interactive logon type.
- The source address `127.0.0.1` is the loopback address and indicates a local context, not an external IP address.
- The failed target account fields were blank/unknown in this record.
- `svchost.exe` is a legitimate Windows executable, but its presence alone does not prove an event is benign.
- Status `0xC000006D` is a logon-failure status. The SubStatus was recorded as `0xC0000380`; its precise interpretation was not independently verified in this exercise.

### Preliminary classification

**Likely benign / consistent with local test activity, but not conclusively correlated.** The event's local loopback context and the lab activity make it plausible that it was related to the test. However, the event did not identify the failed target account, and the details alone do not conclusively prove that this exact event was caused by the intentionally entered incorrect password. A second 4625 event was also present and was not investigated in depth.

## Step 7 — Narrow the timeline and review surrounding events

**Location:** My PC — Web browser — Wazuh Dashboard — Events

Narrowed the dashboard time range to approximately November 20, 2026, 18:30–19:15 local dashboard time to review nearby events.

Events visible in this timeframe included:

- Windows Logon Success (Rule ID 60106, Level 3)
- CVE-2022-30168 affects Photos (Rule ID 23504, Level 7)
- Non service account logged off (Rule ID 67023, Level 3)
- Special privileges assigned to new logon (Rule ID 67028, Level 3)
- Non network or service local logon (Rule ID 67022, Level 3)
- A manager-side Systemd service failure alert (Rule ID 40704) around 19:12:58, which was noted but not investigated further

**Purpose:** Review the broader timeline and identify other events that may provide context. Presence in the same time window does not automatically establish a causal relationship.

## Step 8 — Inspect the special-privileges event

**Location:** My PC — Web browser — Wazuh Dashboard — expanded event

Inspected the **Special privileges assigned to new logon** event (Rule ID 67028).

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

**Interpretation:** These privileges are sensitive and can be abused in some circumstances, but their presence in an event is not proof of misuse. This event's Logon ID differed from the 4625 event's subject Logon ID, so a direct session correlation was not established.

**Preliminary classification:** Likely benign administrative logon context, pending further verification if this were a real incident.

## Step 9 — Inspect a successful service logon

**Location:** My PC — Web browser — Wazuh Dashboard — expanded Windows Logon Success event

Inspected the **Windows Logon Success** event (Rule ID 60106).

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

- Wazuh Manager service and IP verification on Linux
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
