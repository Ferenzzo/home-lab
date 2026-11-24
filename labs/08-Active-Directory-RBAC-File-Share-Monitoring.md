# Lab 08 — Active Directory RBAC & File Share Monitoring

**Date:** November 24, 2026  
**Environment:** Windows Server Active Directory domain `renzzolab.local`; Wazuh 4.12.0; Rocky Linux Wazuh Manager; Windows Server agent  
**Type:** Authorized home-lab access-control and audit investigation

## Objective
Configure and test group-based access to a Windows SMB share, test an authorized and an unauthorized account, and verify that Windows file-share audit events are collected in Wazuh's raw JSON archive.

## Environment
- Domain: `renzzolab.local`
- Domain Controller: `kimchi.renzzolab.local`
- Windows Server IP: `208.8.8.100`
- Wazuh Manager: `208.8.8.128`
- Wazuh version: `4.12.0`
- Share: `SOC-Share`
- Folder: `C:\SOC-Share`
- File: `Confidential.txt`

## 1. Create the security group
```powershell
New-ADGroup -Name "SOC-FileAccess" -GroupScope Global -GroupCategory Security -Path "CN=Users,DC=renzzolab,DC=local"
Get-ADGroup SOC-FileAccess | Select-Object Name, GroupScope, GroupCategory
```

## 2. Create the folder and test file
```powershell
New-Item -Path "C:\SOC-Share" -ItemType Directory
New-Item -Path "C:\SOC-Share\Confidential.txt" -ItemType File
```

## 3. Apply NTFS permissions and create the SMB share
```powershell
icacls "C:\SOC-Share" /grant "RENZZOLAB\SOC-FileAccess:(OI)(CI)R"
New-SmbShare -Name "SOC-Share" -Path "C:\SOC-Share" -ReadAccess "RENZZOLAB\SOC-FileAccess"
Get-SmbShareAccess -Name "SOC-Share"
```
The share and group-based permission configuration were created and checked. Existing inherited folder permissions were also present; this lab does not claim that the group was the folder's exclusive access path.

## 4. Add the authorized test account to the group
```powershell
Add-ADGroupMember -Identity "SOC-FileAccess" -Members "SOC-TestUser"
Get-ADGroupMember -Identity "SOC-FileAccess"
```

## 5. Test authorized access
SMB credential sessions were cleared during testing when necessary:
```powershell
net use \\localhost\SOC-Share /delete
net use \\localhost\SOC-Share /user:RENZZOLAB\SOC-TestUser *
Get-ChildItem \\localhost\SOC-Share
Set-Content -Path "C:\SOC-Share\Confidential.txt" -Value "This is a confidential SOC lab file."
Get-Content \\localhost\SOC-Share\Confidential.txt
```
**Observed:** The authorized test account could access/list the share and read the test file. The file content was verified.

## 6. Create and test an account without group membership
```powershell
New-ADUser -Name "SOC-NoAccess" -SamAccountName "SOC-NoAccess" -AccountPassword (ConvertTo-SecureString "NoAccessLab2026!" -AsPlainText -Force) -Enabled $true
```
The test account was not added to `SOC-FileAccess`.

After disconnecting the prior SMB session, the share connection/access test was attempted using the unauthorized test account. Listing the share produced an access-denied result.

## 7. Enable Detailed File Share auditing
```powershell
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /get /subcategory:"Detailed File Share"
```
Windows Security Event ID **5145** was inspected locally:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -MaxEvents 10 | Format-List TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -MaxEvents 50 | Where-Object { $_.Message -match 'SOC-Share' } | Format-List TimeCreated,Id,Message
```
Events were observed for share-access checks, including the share path and access details.

## 8. Adjust Wazuh event collection and verify agent
The Windows agent's Security-channel query configuration was adjusted to stop excluding Event ID 5145. The other existing exclusions were preserved. The Wazuh agent service was restarted:
```powershell
Restart-Service Wazuh
Get-Service Wazuh
```
Agent status/logs were checked to confirm the service was running and communicating with the manager.

## 9. Enable raw JSON archives on the Wazuh Manager
In `/var/ossec/etc/ossec.conf`, the manager's archive setting was changed to:
```xml
<logall_json>yes</logall_json>
```
The manager was restarted and checked:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```
Archive file:
```
/var/ossec/logs/archives/archives.json
```

## 10. Verify the denied-access event in Wazuh's raw archive
On the Wazuh Manager:
```bash
sudo grep "SOC-Share" /var/ossec/logs/archives/archives.json | grep "SOC-NoAccess" | tail
```

**Verified archived event details from the test:**
- Event ID: **5145**
- Audit outcome: **AUDIT_FAILURE**
- Account: **SOC-NoAccess**
- Domain: **RENZZOLAB**
- Share: **SOC-Share**
- Share path: `\\*\SOC-Share`
- Access check result: **Not granted**
- Requested access included: **ReadAttributes**
- Source address: **::1** (local loopback test)
- Agent: **kimchi**

The denied-access event was found in the Wazuh raw JSON archive. This confirms collection and retention of the event. The event was not verified as a generated Wazuh alert in Threat Hunting, so this lab documents raw-event collection rather than alert-based detection.

## SOC interpretation
- Event 5145 provides detailed information about access checks against a network share.
- The observed failure indicates the requested access was not granted to the account.
- An analyst can use the username, share, requested access, outcome and timestamp to investigate an access attempt.
- Raw archive collection can support investigation even when an event does not produce a visible alert.

## Learning outcomes
- Created and reviewed an Active Directory security group.
- Applied group-based NTFS and SMB share permissions.
- Tested authorized and unauthorized share access.
- Enabled Detailed File Share auditing and examined Event ID 5145.
- Modified Wazuh agent event collection to include 5145.
- Enabled Wazuh JSON archives and verified the raw denied-access event.
- Distinguished archived telemetry from a generated alert.

## Conclusion
The lab demonstrated a basic RBAC/file-share access-control test and verified that Wazuh collected the failed share-access audit event (5145) for the unauthorized test account in its raw JSON archive. The lab did not establish an alert rule or confirm a Threat Hunting alert for this event.
