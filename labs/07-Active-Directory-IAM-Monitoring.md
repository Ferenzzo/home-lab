# Lab 07 — Active Directory IAM Monitoring

**Date:** November 22, 2026  
**Type:** Home Lab / Security Monitoring / Identity and Access Management (IAM)  
**SIEM:** Wazuh 4.12.0  
**Endpoint:** Windows Server (Active Directory Domain Controller)  
**Domain:** `renzzolab.local`  
**Domain Controller / Agent:** WinServer-Lab  
**Wazuh Manager:** `208.8.8.128`  
**Windows Server IP:** `208.8.8.100`

---

## 1. Objective

The objective of this lab was to monitor and investigate Active Directory identity-related activities through Wazuh.

This lab focused on monitoring Windows Security events associated with user account creation, account enabling and modification, failed logon attempts, and privileged group membership changes.

The goal was to understand how a SOC Analyst can use a SIEM to identify, investigate, and assess potentially suspicious identity and access management activities.

## 2. Tools Used

- Windows Server
- Active Directory Domain Services (AD DS)
- Windows PowerShell
- Wazuh 4.12.0
- Wazuh Threat Hunting
- Windows Security Event Log

## 3. Environment

The Windows Server virtual machine was configured as an Active Directory Domain Controller for the domain `renzzolab.local`.

The Windows Server was connected to Wazuh through its Windows agent, allowing Windows Security events to be collected and investigated through the Wazuh dashboard.

The test account used in the lab was:

- **Username:** `SOC-TestUser`
- **Domain:** `RENZZOLAB`
- **Purpose:** Simulate identity-related security activities

## 4. Step-by-Step Procedure

### Step 1 — Verify Active Directory Domain

In Windows Server PowerShell, the Active Directory domain information was checked using:

```powershell
Get-ADDomain
```

This was used to verify the domain configuration and confirm that Active Directory was operational.

### Step 2 — Verify Active Directory Services

The following command was used to check the status of the critical Active Directory services:

```powershell
Get-Service NTDS,DNS,Netlogon
```

The following services were confirmed to be running:

- DNS
- Netlogon
- NTDS (Active Directory Domain Services)

### Step 3 — Review Existing Active Directory Accounts

Existing user accounts were reviewed using:

```powershell
Get-ADUser -Filter * | Select-Object Name,SamAccountName
```

The output included accounts such as:

- Administrator
- Guest
- krbtgt

### Step 4 — Create and Enable the Test Account

A test account named `SOC-TestUser` was used for the lab's identity monitoring activities.

The account was enabled using:

```powershell
Enable-ADAccount SOC-TestUser
```

Its status was subsequently verified:

```powershell
Get-ADUser SOC-TestUser | Select-Object Name,SamAccountName,Enabled
```

The output confirmed:

| Name | Enabled |
|---|---|
| SOC-TestUser | True |

### Step 5 — Monitor Account Creation Events

In Wazuh Threat Hunting, the account creation event was investigated.

**Event ID 4720 — A user account was created.**

The event was observed in Wazuh, confirming that account creation activity was being collected.

### Step 6 — Monitor Account Enablement

The account enablement event was investigated.

**Event ID 4722 — A user account was enabled.**

The event was observed through Wazuh.

### Step 7 — Monitor Account Modification

Account modification activity was reviewed in Wazuh.

**Event ID 4738 — A user account was changed.**

The event was observed through Wazuh, allowing account modification activity to be monitored.

### Step 8 — Simulate Failed Logon Attempts

Failed authentication attempts were generated during the lab.

The following command was used on Windows Server to inspect failed logon events:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 | Format-List TimeCreated,Id,Message
```

The output showed failed logon activity, including:

- Event ID: 4625
- Failure reason: Unknown user name or bad password
- Logon type: 2 in one observed event
- Logon type: 3 in another observed event

The events were also visible in Wazuh.

Wazuh generated alerts associated with failed logons, including:

- **Rule ID 60122:** Logon Failure - Unknown user or bad password
- **Rule ID 60204:** Multiple Windows Logon Failures

Rule ID 60204 was observed at Level 10.

The multiple failed logons demonstrated how repeated authentication failures can trigger a higher-level alert.

### Step 9 — Investigate Failed Logon Activity

The failed logon event was examined in Wazuh Threat Hunting.

The event details included fields such as:

- `data.win.system.eventID`
- `data.win.eventdata.ipAddress`
- `data.win.eventdata.targetUserName`
- `data.win.eventdata.logonType`
- `data.win.eventdata.status`
- `data.win.eventdata.subStatus`
- `data.win.eventdata.logonProcessName`

The observed event included the source IP address:

`208.8.8.1`

The target account shown in one of the observed events was:

`administrator`

The failed logon activity was investigated as part of the authentication monitoring exercise.

### Step 10 — Simulate Privileged Group Membership Change

The test account was added to the Domain Admins group to simulate a sensitive privilege modification.

Command used:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "SOC-TestUser"
```

This simulated a privileged group membership change.

### Step 11 — Investigate the Group Membership Change in Wazuh

The following event was investigated:

**Event ID 4728 — A member was added to a security-enabled global group.**

The event was observed in Wazuh Threat Hunting.

The event details showed:

- **Actor:** Administrator
- **Target group:** Domain Admins
- **Member added:** SOC-TestUser
- **Domain:** RENZZOLAB
- **Event ID:** 4728

The member information included:

`CN=SOC-TestUser,CN=Users,DC=renzzolab,DC=local`

The event confirmed that Wazuh collected the privileged group membership modification.

### Step 12 — Verify Domain Admins Membership

The Domain Admins group membership was inspected using:

```powershell
Get-ADGroupMember "Domain Admins"
```

The test account was confirmed to have been added during the simulation.

### Step 13 — Remove the Test Account from Domain Admins

After the investigation, the test account was removed from the privileged group.

Command used:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "SOC-TestUser" -Confirm:$false
```

This was performed to undo the simulated privilege change.

### Step 14 — Verify the Removal

The group membership was checked again:

```powershell
Get-ADGroupMember "Domain Admins"
```

The resulting output showed only:

`Administrator`

SOC-TestUser was no longer listed, confirming the removal.

---

## 5. Wazuh Events Investigated

| Event ID | Event Description | Result |
|---|---|---|
| 4720 | User account created | Observed |
| 4722 | User account enabled | Observed |
| 4738 | User account changed | Observed |
| 4625 | Failed logon attempt | Observed |
| 4728 | Member added to security-enabled global group | Observed |

### Wazuh Rules Observed

| Rule ID | Description | Level |
|---|---|---:|
| 60122 | Logon Failure - Unknown user or bad password | 5 |
| 60204 | Multiple Windows Logon Failures | 10 |

---

## 6. Investigation Findings

The lab demonstrated that Wazuh was collecting and displaying Windows Security events related to identity and authentication activities.

The following activities were successfully investigated:

- User account creation
- Account enablement
- Account modification
- Failed logon attempts
- Multiple failed logon detections
- Privileged group membership changes

The Domain Admins membership modification was particularly important because privileged group changes can significantly affect the security of an organization.

The investigation confirmed:

- Administrator performed the simulated group modification.
- SOC-TestUser was added to Domain Admins.
- The modification was logged as Event ID 4728.
- The account was subsequently removed.
- The removal was verified through Active Directory group membership inspection.

---

## 7. SOC Analyst Interpretation

In a real organization, adding an account to the Domain Admins group would be considered a sensitive security event requiring investigation.

A SOC Analyst should determine:

1. Who performed the change?
2. Which account was added?
3. Which privileged group was modified?
4. Was the change approved?
5. Was the activity associated with a legitimate administrative task?
6. Does the activity correlate with other suspicious events?
7. Should the activity be escalated to the Incident Response or IT Security team?

An unauthorized addition to a privileged group may indicate privilege escalation or account compromise.

The analyst should not automatically classify every privileged group modification as malicious. Authorization, context, timing, and related events must be reviewed.

---

## 8. Commands Used

### Active Directory Domain Verification

```powershell
Get-ADDomain
```

### Service Verification

```powershell
Get-Service NTDS,DNS,Netlogon
```

### Review Active Directory Accounts

```powershell
Get-ADUser -Filter * | Select-Object Name,SamAccountName
```

### Enable Test Account

```powershell
Enable-ADAccount SOC-TestUser
```

### Verify Account Status

```powershell
Get-ADUser SOC-TestUser | Select-Object Name,SamAccountName,Enabled
```

### Review Failed Logon Events

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 | Format-List TimeCreated,Id,Message
```

### Add Test Account to Domain Admins

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "SOC-TestUser"
```

### Verify Domain Admins Membership

```powershell
Get-ADGroupMember "Domain Admins"
```

### Remove Test Account from Domain Admins

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "SOC-TestUser" -Confirm:$false
```

### Verify Removal

```powershell
Get-ADGroupMember "Domain Admins"
```

---

## 9. Learning Outcomes

Through this lab, I learned how to:

- Monitor Active Directory account-related activities using Wazuh.
- Investigate Windows Security events.
- Identify failed logon attempts.
- Understand how repeated authentication failures can trigger higher-level SIEM alerts.
- Monitor account creation, enablement, and modification.
- Investigate privileged group membership changes.
- Identify the actor and target account involved in a security event.
- Understand the security implications of Domain Admins membership.
- Verify the removal of unnecessary privileged access.
- Apply basic SOC investigation principles to identity and access management events.

---

## 10. Conclusion

This lab demonstrated the use of Wazuh as a SIEM for monitoring Active Directory identity and authentication activities.

By generating controlled events in a Windows Server Active Directory environment and investigating them through Wazuh, I gained hands-on experience with account monitoring, failed logon detection, and privileged group membership investigation.

These activities represent common tasks performed by SOC Analysts when investigating suspicious authentication and identity-related activities.

**Lab Status: Completed**
