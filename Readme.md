## CrowdStrike Reporting Tool for Azure (CRT)

This tool queries the following configurations in the Azure AD/O365 tenant which can shed light on hard to find permissions and configuration settings in order to assist organizations in securing these environments.

Exchange Online (O365):
- Federation Configuration
- Federation Trust
- Client Access Settings Configured on Mailboxes
- Mail Forwarding Rules for Remote Domains
- Mailbox SMTP Forwarding Rules
- Delegates with 'Full Access' Permission Granted
- Delegates with Any Permissions Granted
- Delegates with 'Send As' or 'SendOnBehalf' Permissions
- Exchange Online PowerShell Enabled Users
- Users with 'Audit Bypass' Enabled
- Mailboxes Hidden from the Global Address List (GAL)

Azure AD:
- Service Principal Objects with KeyCredentials
- O365 Admin Groups Report
- Delegated Permissions & Application Permissions

Querying Tenant Partner Information:
NOTE: In order to view Tenant Partner Information, including roles assigned to your partners, you must log into the Azure Admin Portal as Global Admin:

https://admin.microsoft.com/AdminPortal/Home#/partners

### Prerequisites:
The following PowerShell modules are required and will be installed automatically:
- ExchangeOnlineManagement
- AzureAD

NOTE: To return the full extent of the configurations being queried, the following role is required:
- Global Admin

When Global Admin privileges are not available, the tool will notify you about what information won’t be available to you as a result.

### Usage:

No parameters specified: _A folder named with date and time (YYYYDDMMTHHMM) will be created automatically in the directory the script is being run from. Default authentication method will prompt for each connection for compatibility with MFA._
```
.\Get-CRTReport.ps1
```
`-BasicAuth` Parameter:
_[OPTIONAL] If MFA is not enforced for your user principal, you can use this parameter which will prompt only once for authentication and store credentials using `Get-Credential`. (Not Recommended)_
```
.\Get-CRTReport.ps1 -BasicAuth
```
`-JobName` Parameter:
_[OPTIONAL] Use the JobName parameter to distinguish between different tenants. If no JobName is specified, a Date/Time formatted folder will be placed within the working directory._
```
.\Get-CRTReport.ps1 -JobName MyJobName
```
`-WorkingDirectory` Parameter:
_[OPTIONAL] If you want to specify a different working directory for your jobs, you can do so with this parameter. The default working directory is the directory the script is being run from._
```
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job\Folder'
```
`-Commands` Parameter:
_[OPTIONAL] With this parameter, specify the specific commands you want to run in quotes, comma or space separated._
```
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job\Folder' -Commands "Command1,Command2"
```
Available Commands:
```
FedConfig
FedTrust
ClientAccess
RemoteDomains
SMTPForward
FullAccessGranted
AnyAccessGranted
SendAsGranted
EXOPowerShell
AuditBypassEnabled
HiddenMailboxes
KeyCredentials
O365AdminGroups
DelegateAppPerms
```

`-Interactive` Parameter:
_[OPTIONAL] Some commands may take a long time to process depending on the amount of data in the tenant. Using the Interactive parameter, you will have the option to skip any particular command prior to the module running._
```
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job\Folder' -Interactive
```

### Report Summary:
With each run, CRT will output a report for each query in json as well as more readable, .TXT and .CSV formats:

No parameters specified: _A folder named with date and time (YYYYDDMMTHHMM) will be created automatically in the directory the script is being run from. To support MFA, the default authentication method will prompt the user to login for each connection._
- `YYYYDDMMTHHMM\output.log` (hard copy of console logging)
- `YYYYDDMMTHHMM\_CRTReportSummary.txt` (Summary of scripts run and investigative tips for guidance)
- `YYYYDDMMTHHMM\Reports\<report>.csv` (Report in CSV output, where applicable)
- `YYYYDDMMTHHMM\Reports\<report>.txt` (Report in TXT output, where applicable)
- `YYYYDDMMTHHMM\Reports\json\<report>.json` (Each report is accompanied by JSON output for additional verbosity)

### Known Issues:

- Attempting to connect to Exchange Online using Federated logins does not currently work while trying to connect to both Exchange Online and Azure AD in the same PowerShell Session.
- Retrieving results for Any/FullAccess permissions (AnyAccessGranted and FullAccessGranted commands) in some cases returns an error and may not fully complete. Running the command manually may still work:
```
Get-EXOMailbox -ResultSize Unlimited | Get-EXOMailboxPermission | Where-Object { ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")} | Export-Csv "AnyAssignedPerms.csv" -NoTypeInformation

Get-EXOMailbox -ResultSize Unlimited | Get-EXOMailboxPermission | Where-Object { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")} | Export-Csv "FullAccessPerms.csv" -NoTypeInformation
```

### How Can I Contribute?

If you've found a bug, please use the Issues tab to report a new issue or add your comments to an existing one.

If you have any recommendations for the tool, or require critical escalation, please email: CRT@crowdstrike.com