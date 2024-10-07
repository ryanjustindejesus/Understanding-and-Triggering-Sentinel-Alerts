<h1>Understanding and Triggering Sentinel Alerts</h1>

- <b>This tutorial outlines the configuration of incidents using Microsoft Sentinel </b>

<h2>Environments and Technologies Used</h2>

- <b>Microsoft Azure</b>
- <b>Microsoft Sentinel</b>
- <b>Virtual Machines</b>
- <b>Log Analytics Workspace</b>
- <b>Azure Active Directory</b>

<h2>Operating Systems</h2>

- <b>Windows 10</b>

<h2>Configuration Steps</h2>

- <b>Login to your attack-vm and simulate a brute force success against your Azure Active Directory</b>
- <b>Open portal.azure.com and fail 10 logins in a row followed by a successful login</b>

![image](https://github.com/user-attachments/assets/5b1a9eb8-95a5-4798-bd31-f4db0d4a909d)
- <b>Navigate to Microsoft Sentinel and select Custom Brute Force Success - Azure Active Directory (AAD)</b>

![image](https://github.com/user-attachments/assets/9513e051-2a2e-4932-a869-7d5007bba88d)
- <b>Click set rule logic and copy the rule query</b>
```
// Failed AAD logon
let FailedLogons = SigninLogs
| where Status.failureReason == "Invalid username or password or Invalid on-premise username or password."
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.failureReason, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize FailureCount = count() by AttackerIP, UserPrincipalName;
let SuccessfulLogons = SigninLogs
| where Status.errorCode == 0 
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.errorCode, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize SuccessCount = count() by AuthenticationSuccessTime = TimeGenerated, AttackerIP, UserPrincipalName, UserId, UserDisplayName;
let BruteForceSuccesses = SuccessfulLogons
| join kind = inner FailedLogons on AttackerIP, UserPrincipalName;
BruteForceSuccesses
| project AttackerIP, TargetAccount = UserPrincipalName, UserId, FailureCount, SuccessCount, AuthenticationSuccessTime
```

![image](https://github.com/user-attachments/assets/49735f20-848c-495e-9a37-b9f271e4e481)
- <b>Navigate to Log Analytics Workspace and observe the failed and successful login attempts to your Azure Active Directory using your attack-vm</b>

![image](https://github.com/user-attachments/assets/7fa56c6b-cd29-4459-9d27-5e5fbfa8fee2)
- <b>Login to your windows-vm and open Powershell ISE</b>
- <b>Copy and paste this query and save it as a raw file into windows-vm desktop
- Run the query into PowerShell ISE to generate a Malware alert using an EICAR file:

```
﻿$TOTAL_VIRUSES_TO_MAKE = 1

$firsthalf = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
$secondhalf = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

$count = 0

while ($count -lt $TOTAL_VIRUSES_TO_MAKE) {

    Write-Host "Generating: EICAR-$($count).txt"
    "$($firsthalf)$($secondhalf)" | Out-File -FilePath "EICAR-$($count).txt"
    $count++
}
```

![image](https://github.com/user-attachments/assets/31ffdb25-8163-494f-8fcc-01da5099eb2d)
- <b>Open the Event Viewer in your windows-vm</b>
- <b>Navigate to this file path: Navigate to this file path: Microsoft-Windows-Windows Defender/Operational</b>
- <b>Observe the generated EICAR file</b>

![image](https://github.com/user-attachments/assets/6b6e4be6-feec-4322-805e-4a3f06fe6e5f)
- <b>Navigate to Key vaults and click secrets</b>
- <b>Select Tenant-Global-Admin-Password and click secret value</b>

![image](https://github.com/user-attachments/assets/cdf47bbf-3faa-437f-8f7c-27e09e99a552)
- <b>Navigate to Microsoft Sentinel and select CUSTOM: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)</b>
- <b>Click set rule logic and copy the rule query:
```
// Updating a specific existing password Success
let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" 
| where OperationName == "SecretGet" or OperationName == "SecretSet"
| where id_s contains CRITICAL_PASSWORD_NAME
```

![image](https://github.com/user-attachments/assets/e9bb1692-2f83-4697-bf31-80f374238dbf)
- <b>Navigate to Log Analytics Workspace and paste the ruley query</b>
- <b>Observe the log for viewing the secret value for the Tenant-Global-Admin-Password</b>

![image](https://github.com/user-attachments/assets/4a28a551-f47a-4b96-894e-001b006a80ef)
- <b>Navigate to Microsoft Sentinel and click analytics and select CUSTOM: Possible Lateral Movement (Excessive Password Resets)</b>
- Click set rule logic and copy the rule query:
```
AuditLogs
| where OperationName startswith "Change" or OperationName startswith "Reset"
| order by TimeGenerated
| summarize count() by tostring(InitiatedBy)
| project Count = count_, InitiatorId = parse_json(InitiatedBy).user.id, InitiatorUpn = parse_json(InitiatedBy).user.userPrincipalName, InitiatorIpAddress = parse_json(InitiatedBy).user.ipAddress 
| where Count >= 10
```

![image](https://github.com/user-attachments/assets/d57ee936-d19f-41ef-beff-54a0781bd2ba)
- <b>Navigate to Azure Active Directory and click users</b>
- <b>Select dummy_user and reset password multiple times</b>
- <b>Navigate to Log Analytics Workspace and observe the logs for the excessive password resets using the query above</b>

![image](https://github.com/user-attachments/assets/5d69a815-92af-435f-9503-a03b1d553a37)
- <b>Microsoft Sentinel Incidents</b>
- <b>Let your windows-vm and linux-vm runs for 24 hours</b>
