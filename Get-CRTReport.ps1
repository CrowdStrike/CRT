#Requires -Module ExchangeOnlineManagement,AzureAD

<#
.SYNOPSIS
Retrieves various configurations from the Azure AD/O365 tenant to provide insight during threat hunting.

.DESCRIPTION 
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

.OUTPUTS
This tool will return most queries in .CSV format, and a few in .TXT format. Additionally, all JSON results will be in the 'json' subdirectory.

.PARAMETER JobName
[OPTIONAL] Use the JobName parameter to distinguish between different customer tenants. If no JobName is specified, a Date/Time formatted folder will be placed within the working directory.

.PARAMETER WorkingDirectory
[OPTIONAL] If you want to specify a different working directory for your jobs, you can do so with this parameter. The default working directory is the directory the script is being called from.

.PARAMETER Commands
[OPTIONAL] With this parameter, specify the specific commands you want to run in quotes, comma or space separated.

.PARAMETER Interactive
[OPTIONAL] Some commands may take a long time to process depending on the amount of data in the tenant. Using the Interactive parameter, you will have the option to skip any particular command prior to the module running.

.EXAMPLE
.\Get-CRTReport.ps1

.EXAMPLE
.\Get-CRTReport.ps1 -JobName MyJobName

.EXAMPLE
.\Get-CRTReport.ps1 -WorkingDirectory 'C:\Path\to\Job'

.EXAMPLE
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job'

.EXAMPLE
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job' -Interactive

.EXAMPLE
.\Get-CRTReport.ps1 -JobName MyJobName -WorkingDirectory 'C:\Path\to\Job' -Commands "Command1,Command2"

.NOTES
CrowdStrike Reporting Tool for Azure (CRT)
Written by CrowdStrike Endpoint Recovery Services

Version history:
V1.0, 12/23/2020 - Initial version

License:
Copyright (c) 2020 CrowdStrike
Copyright (c) 2020 panavarr
Copyright (c) 2017 Paul Cunningham

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>

Param (
    [Switch]$BasicAuth,
    [String]$Commands,
    [Switch]$Interactive,
    [String]$JobName,
    [System.IO.FileInfo]$WorkingDirectory
);

#...................................
# Functions
#...................................

# Function to process results to _CRTReportSummary.txt
Function Out-Summary {
    Param
    (
        [string]$string,
        [switch]$NewReport,
        [switch]$Summary
    )

    # Get the current date
    [string]$date = [DateTime]::UtcNow.ToString((Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern);

    # Get _CRTReportSummary.txt file path
    $SummaryFile = Join-path $LogDirectory "_CRTReportSummary.txt";
    if(-not(Test-Path $SummaryFile)) {
        # Create new _CRTReportSummary.txt file
        [string]$ReportHeader = "##################################################################`r####### CrowdStrike Reporting Tool for Azure (CRT) Summary #######`r#################################################################`r`rReview the following findings from your query for anomalies. Refer to the investigative tips in each section for guidance.";
        $ReportHeader | Out-File -FilePath $SummaryFile
    };

    if($NewReport) {
        [string]$sumstring = ("`r### " + $string +  "  ###")
    }
    elseif ($Summary) {        
        [string]$sumstring = ($string)
    }
    else {
        [string]$sumstring = ( "[" + $date + "] - " + $string)
    };

    # Write everything to our report summary file
    if ($null -ne $sumstring) {
        $sumstring | Out-File -FilePath $SummaryFile -Append
    }
};

# Function to process results to output.log
Function Out-LogFile {
    Param 
    ( 
        [string]$string,
        [switch]$warning
    )
	
    # Get our log file path
    $LogFile = Join-path $LogDirectory "output.log";
    $ScreenOutput = $true;
    $LogOutput = $true;
	
    # Get the current date
    [string]$date = [DateTime]::UtcNow.ToString((Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern);
    
    # If -warning is set
    if ($warning) {
        [string]$logstring = ("[" + $date + "] - [WARNING] - " + $string);
        $ScreenOutput = $false
        
    }
    # Normal output
    else {
        [string]$logstring = ( "[" + $date + "] - " + $string)
    };

    # Write everything to output.log file
    if ($LogOutput) {
        $logstring | Out-File -FilePath $LogFile -Append
    };
	
    # Output to the screen
    if ($ScreenOutput) {
        Write-Information -MessageData $logstring -InformationAction Continue
    }

};

#..........................................
# Functions for AzureADPSPermissions Script
#..........................................

# Function to add an object to the cache
function CacheObject ($Object) {
    if ($Object) {
        if (-not $script:ObjectByObjectClassId.ContainsKey($Object.ObjectType)) {
            $script:ObjectByObjectClassId[$Object.ObjectType] = @{}
        }
        $script:ObjectByObjectClassId[$Object.ObjectType][$Object.ObjectId] = $Object;
        $script:ObjectByObjectId[$Object.ObjectId] = $Object
    }
};

# Function to retrieve an object from the cache (if it's there), or from Azure AD (if not).
function GetObjectByObjectId ($ObjectId) {
    if (-not $script:ObjectByObjectId.ContainsKey($ObjectId)) {
        Write-Verbose ("Querying Azure AD for object '{0}'" -f $ObjectId);
        try {
            $object = Get-AzureADObjectByObjectId -ObjectId $ObjectId;
            CacheObject -Object $object
        } catch {
            Write-Verbose "Object not found."
        }
    };
    return $script:ObjectByObjectId[$ObjectId]
};

function GetOAuth2PermissionGrants ([switch]$FastMode) {
    if ($FastMode) {
        Get-AzureADOAuth2PermissionGrant -All $true
    } else {
        $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {
            Write-Progress -Activity "Retrieving delegated permissions..." `
                            -Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
                            -PercentComplete (($i / $servicePrincipalCount) * 100);

            $client = $_.Value;
            Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $client.ObjectId
        }
    }
};

#..............................................
# Ensure -Commands includes at least one module
#..............................................

if ($Commands) {
    $availableCommands = @(
        "FedConfig",
        "FedTrust",
        "ClientAccess",
        "RemoteDomains",
        "SMTPForward",
        "FullAccessGranted",
        "AnyAccessGranted",
        "SendAsGranted",
        "EXOPowerShell",
        "AuditBypassEnabled",
        "HiddenMailboxes",
        "KeyCredentials",
        "O365AdminGroups",
        "DelegateAppPerms"
    );
    $SplitChar = [regex]::Match($Commands,"\W").Value;
    $allCommands = $Commands.Split($SplitChar);
    $goodCommands = 0;
    foreach ($CommandFound in $allCommands) {
        if ($availableCommands.Contains($CommandFound)) {
            $goodCommands += 1
        }
    };
    if ($goodCommands -eq 0) {
        Write-Host -ForegroundColor Red "No modules found to run. Be sure to specify at least one of the following:"
        foreach ($availableCommand in $availableCommands) {
            Write-Host -ForegroundColor Red " - $availableCommand"
        };
        return
    }
};

#...................................
# Build Working Directory Structure
#...................................

if ($WorkingDirectory -and $JobName) {
    if (-not (Test-Path -Path $WorkingDirectory)) {
        New-Item -Path $WorkingDirectory -ItemType "directory" | Out-Null
    };
    
    $baseFolder = (Resolve-Path -Path $WorkingDirectory).Path;
    $jobFolder = "$baseFolder\$JobName";
    
    if (-not (Test-Path -Path $jobFolder)) {
        New-Item -Path $jobFolder -ItemType "directory" | Out-Null
    };
    
    $runTime = Get-Date -Format "yyyyMMddTHHmm";
    $runFolder = "$jobFolder\$runTime";
    
    if (-not (Test-Path -Path $runFolder)) {
        New-Item -Path $runFolder -ItemType "directory" | Out-Null
    }
} elseif ($WorkingDirectory) {
    if (-not (Test-Path -Path $WorkingDirectory)) {
        New-Item -Path $WorkingDirectory -ItemType "directory" | Out-Null
    };
    
    $baseFolder = (Resolve-Path -Path $WorkingDirectory).Path;
    
    $runTime = Get-Date -Format "yyyyMMddTHHmm";
    $runFolder = "$baseFolder\$runTime";
    
    if (-not (Test-Path -Path $runFolder)) {
        New-Item -Path $runFolder -ItemType "directory" | Out-Null
    }
} elseif ($JobName) {
    if (-not (Test-Path -Path $JobName)) {
        New-Item -Path $JobName -ItemType "directory" | Out-Null
    };
    
    $baseFolder = (Resolve-Path -Path $JobName).Path;
    $runTime = Get-Date -Format "yyyyMMddTHHmm";
    $runFolder = "$baseFolder\$runTime";
    
    if (-not (Test-Path -Path $runFolder)) {
        New-Item -Path $runFolder -ItemType "directory" | Out-Null
    }
} else {
    $baseFolder = (Get-Item -Path .).FullName;
    
    $runTime = Get-Date -Format "yyyyMMddTHHmm";
    $runFolder = "$baseFolder\$runTime";
    
    if (-not (Test-Path -Path $runFolder)) {
        New-Item -Path $runFolder -ItemType "directory" | Out-Null
    }
};

if ($JobName) {
    $baseFolderName = $JobName
} else {
    $baseFolderName = (Get-Item -Path $baseFolder).Name
};

$Global:runFolderShort = "$baseFolderName\$((Get-Item -Path $runFolder).Name)";
$Global:reportsFolder = Join-Path -Path $runFolder -ChildPath "Reports";

if (-not (Test-Path -Path $reportsFolder)) {
    New-Item -Path $reportsFolder -ItemType "directory" | Out-Null
};

$Global:jsonFolder = Join-Path -Path $reportsFolder -ChildPath "json";

if (-not (Test-Path -Path $jsonFolder)) {
    New-Item -Path $jsonFolder -ItemType "directory" | Out-Null
}; # Output should be saved to the $runFolder directory.

# Set LogDirectory global variable for logging functions
$Global:LogDirectory = $runFolder;

# Check for the Azure AD and Exchange Online Management Modules, and install if not already available
Out-LogFile "Checking for PowerShell module prerequisites"
if (-not (Get-Module -Name ExchangeOnlineManagement)) {
    try {
        Out-LogFile "Installing ExchangeOnlineManagement module";
        Install-Module -Name ExchangeOnlineManagement -Force
    } catch {
        Write-Host -ForegroundColor Yellow "[!] Unable to install module ExchangeOnlineManagement. Please be sure to launch an elevated PowerShell prompt."
    }
};
if (-not (Get-Module -Name AzureAD)) {
    try {
        Out-LogFile "Installing AzureAD module";
        Install-Module -Name AzureAD -Force
    } catch {
        Write-Host -ForegroundColor Yellow "[!] Unable to install module AzureAD. Please be sure to launch an elevated PowerShell prompt."
    }
};

#...................................
# Authentication
#...................................

# Create a login credential variable
if ($BasicAuth -and (-not $loginCreds)) {
    $Global:loginCreds = Get-Credential
} elseif (-not $BasicAuth) {
    Write-Host -ForegroundColor Yellow "NOTE: Using default authentication. This method will prompt you for login credentials 3 times.";
    Start-Sleep -Seconds 5
};

Out-LogFile "Beginning authentication";
Out-LogFile "Authenticating to Exchange Online";
# Connect to Exchange Online
try {
    if ($BasicAuth) {
        Connect-ExchangeOnline -Credential $loginCreds -ShowBanner:$false -ErrorAction Stop 6>$null
    } else {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
    };
    Out-LogFile "Successfully connected to Exchange Online"
} catch {
    if($_.Exception.Message -match "you have exceeded the maximum number of connections allowed"){
        try {
            Disconnect-ExchangeOnline -Confirm:$false 6>$null;
            Out-LogFile "Disconnected from previous Exchange Online session(s)"
        } catch {
            throw $_.Exception.Message
        };
        try {
            if ($BasicAuth) {
                Connect-ExchangeOnline -Credential $loginCreds -ShowBanner:$false -ErrorAction Stop 6>$null
            } else {
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
            };
            Out-LogFile "Successfully connected to Exchange Online"
        } catch {
            throw $_.Exception.Message
        }
    } else {
        throw $_.Exception.Message
    }
};
Out-LogFile "Authenticating to Azure AD";
# Connect to Azure AD
try {
    if ($BasicAuth) {
        $ConnectAZD = Connect-AzureAD -Credential $loginCreds -ErrorAction Stop 6>$null
    } else {
        $ConnectAZD = Connect-AzureAD -ErrorAction Stop 6>$null
    };
    Out-LogFile "Successfully connected to Azure AD"
} catch {
    if($_.Exception.Message -match "you have exceeded the maximum number of connections allowed"){
        try {
            Disconnect-AzureAD | Out-Null;
            Out-LogFile "Disconnected from previous Azure AD session(s)"
        } catch {
            Write-Error $_.Exception.Message
        };
        try {
            if ($BasicAuth) {
                $ConnectAZD = Connect-AzureAD -Credential $loginCreds -ErrorAction Stop 6>$null
            } else {
                $ConnectAZD = Connect-AzureAD -ErrorAction Stop 6>$null
            };
            Out-LogFile "Successfully connected to Azure AD"
        } catch {
            throw $_.Exception.Message
        }
    } else {
        throw $_.Exception.Message
    }
};

#...................................
# Script Commands
#...................................

if ($Interactive) {
    $InteractiveMessage = "Press any key to skip this module...";
    $InteractiveSkipMessage = "Skipping module.";
    $InteractiveContMessage = "Running module...";
    $InteractiveWaitSeconds = 3
};

#............................................................................................................................................
# Begin Command: FedConfig (Review Federation Configuration)
#
$moduleMessage = "Retrieving Federation configuration information";
if ($Commands -and $Commands -notmatch "FedConfig") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true;;
        };
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    try {
        $FedConfig = Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo;
        if($null -ne $FedConfig) {
            try {
                $FedConfig | Out-File "$reportsFolder\FederationConfiguration.txt"
            } catch {
                Out-LogFile "Unable to write 'FederationConfiguration.txt' to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write 'FederationConfiguration.txt' to disk"
            };
            try {
                $FedConfig | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\FederationConfiguration.json"
            } catch {
                Out-LogFile "Unable to write 'FederationConfiguration.json' to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write 'FederationConfiguration.json' to disk"
            };
            try {
                Out-LogFile "[+] Review Federation configuration. Output saved to '$runFolderShort\Reports\FederationConfiguration.txt'";
                Out-Summary "Federation Configuration" -NewReport;
                Out-Summary "[+] Review Federation configuration. Output saved to '$runFolderShort\Reports\FederationConfiguration.txt'";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Review existing Federations. Identify unauthorized or unrecognized Federations then revoke them.
                - Threat actors can create unauthorized federations and use them to log into your tenant and perform actions. The user accounts used to do this will not appear in your directory, thereby allowing the threat actor to persist longer.
                - NOTE: This is a known SUNBURST TTP." -Summary
            } catch {
                Out-LogFile "There was a problem logging the Federation Configuration query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging the Federation Configuration query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Federation configuration. Check user permissions" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Federation configuration. Check user permissions"
    };
    # End Module Run
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: FedConfig
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: FedTrust (Review Federation Trust Information)
#
$moduleMessage = "Retrieving Federation trust information"
if ($Commands -and $Commands -notmatch "FedTrust") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    try {
        $FedTrust = Get-FederationTrust;
        if($null -ne $FedTrust) {
            try {
                $FedTrust | Format-List | Out-File "$reportsFolder\FederationTrust.txt";
                $FedTrust | ConvertTo-Json | Out-File "$jsonFolder\FederationTrust.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile "[+] Review Federation trust information. Output saved to '$runFolderShort\Reports\FederationTrust.txt'";
                Out-Summary "Federation Trust Information" -NewReport;
                Out-Summary "[+] Review Federation trust. Output saved to '$runFolderShort\Reports\FederationTrust.txt'";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Review the certificates for the trust. Investigate any recent changes based on date and ensure they are authorized & expected.
                - NOTE: This is a known SUNBURST TTP." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Federation trust information" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Federation trust information"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: FedTrust
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: ClientAccess (Client Access Settings Configured on Mailboxes)
#
$moduleMessage = "Retrieving Client Access Settings Configured on Mailboxes";
if ($Commands -and $Commands -notmatch "ClientAccess") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $ClientAccessSettings = $null;
    try {
        [array]$ClientAccessSettings = Get-EXOCASMailbox -ResultSize Unlimited;
        if($ClientAccessSettings.Count -gt 0) {
            try {
                $ClientAccessSettings | Export-Csv "$reportsFolder\ClientAccessSettingsMailboxes.csv" -NoTypeInformation;
                $ClientAccessSettings | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\ClientAccessSettingsMailboxes.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $ClientAccessSettings.count + " Client Access Settings on Mailboxes");
                Out-LogFile "[+] Review Client Access Settings Configured on Mailboxes. Output saved to '$runFolderShort\Reports\ClientAccessSettingsMailboxes.csv'";
                Out-Summary "Client Access Settings Configured on Mailboxes" -NewReport;
                Out-Summary ("[+] Found " + $ClientAccessSettings.count + " Client Access Settings on Mailboxes");
                Out-Summary "[+] Review Client Access Settings Configured on Mailboxes. Output saved to '$runFolderShort\Reports\ClientAccessSettingsMailboxes.csv'";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Review for any legacy protocols being used (SMTP, IMAP, ActiveSync, POP, etc.).
                - Legacy protocols can be used to access sensitive data without using MFA.
                - Risk for being used for testing password stuffing attacks which can later be used to try to log into VPNs without MFA." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Client Access Settings Configured on Mailboxes" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Client Access Settings Configured on Mailboxes"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: ClientAccess
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: RemoteDomains (Mail Forwarding Rules for Remote Domains)
#
$moduleMessage = "Retrieving Mail Forwarding Rules for Remote Domains";
if ($Commands -and $Commands -notmatch "RemoteDomains") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $RemoteDomains = $null;
    try {
        [array]$RemoteDomains = Get-RemoteDomain | Select-Object Name,DomainName,AllowedOOFType;
        if($RemoteDomains.Count -gt 0) {
            try {
                $RemoteDomains | Export-Csv "$reportsFolder\RemoteDomainNames.csv" -NoTypeInformation;
                $RemoteDomains | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\RemoteDomainNames.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $RemoteDomains.count + " Remote Domain(s)");
                Out-LogFile "[+] Review Mail Forwarding Rules for Remote Domains. Output saved to '$runFolderShort\Reports\RemoteDomainNames.csv'";
                Out-Summary "Mail Forwarding Rules for Remote Domains" -NewReport;
                Out-Summary ("[+] Found " + $RemoteDomains.count + " Remote Domain(s)");
                Out-Summary "[+] Review Mail Forwarding Rules for Remote Domains. Output saved to '$runFolderShort\Reports\RemoteDomainNames.csv'";
                Out-Summary "`rINVESTIGATIVE TIPS:`nNOTE: These are the domains auto-forwarding is allowed to forward to
                - Look for any domain names that are suspicious in nature.
                - Threat Actors can add forwarding rules to send messages to mailboxes they control.
                - Ability to forward to remote domains should be either disabled or restricted.
                - The default setting when remote forwarding is enabled is a wildcard (“*”) but domains list should be limited to trusted & approved email domains, such as for subsidiaries/parent organizations and contractor staff.
                - Retrieving hidden rules is outside of this tool's scope." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Mail Forwarding Rules for Remote Domains" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Mail Forwarding Rules for Remote Domains"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: RemoteDomains
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: SMTPForward (Mailbox SMTP forwarding for All Mailboxes)
#
$moduleMessage = "Retrieving Mailbox SMTP forwarding rules for all mailboxes";
if ($Commands -and $Commands -notmatch "SMTPForward") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $SMTPForward = $null;
    try {
        [array]$SMTPForward = Get-EXOMailbox -ResultSize Unlimited | Where-Object {($_.ForwardingAddress -ne $null -or $_.ForwardingSMTPAddress -ne $null)} | Select-Object Name,ForwardingAddress,ForwardingSMTPAddress,DeliverToMailboxAndForward;
        if($SMTPForward.Count -gt 0) {
            try {
                $SMTPForward | Export-Csv "$reportsFolder\MailForwardingRules.csv" -NoTypeInformation;
                $SMTPForward | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\MailForwardingRules.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $SMTPForward.count + " Mailbox SMTP forwarding rule(s)");
                Out-LogFile "[+] Review Mailbox SMTP forwarding rules for all mailboxes. Output saved to '$runFolderShort\Reports\MailForwardingRules.csv'";
                Out-Summary "Mailbox SMTP Forwarding Rules" -NewReport;
                Out-Summary ("[+] Found " + $SMTPForward.count + " Mailbox SMTP forwarding rule(s)");
                Out-Summary "[+] Review Mailbox SMTP forwarding rules for all mailboxes. Output saved to '$runFolderShort\Reports\MailForwardingRules.csv'";
                Out-Summary "`rINVESTIGATIVE TIPS:
    - Review all forwarding addresses for each mailbox and verify they are legitimate and approved.
    " -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Mailbox SMTP forwarding rules for all mailboxes" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Mailbox SMTP forwarding rules for all mailboxes"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: SMTPForward
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: FullAccessGranted (Mailbox Delegates where "Full Access" Permission is Granted)
#
$moduleMessage = "Retrieving Mailbox Delegates where 'Full Access' permission is granted";
if ($Commands -and $Commands -notmatch "FullAccessGranted") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    Write-Host -ForegroundColor Yellow "This make take awhile; please be patient...";
    $FullAccessPerms = @();
    $FullAccessPermsResults = @();
    try {
        $FullAccessPerms += Get-EXOMailbox -ResultSize Unlimited -ErrorAction SilentlyContinue  | Get-EXOMailboxPermission -ErrorAction Stop | Where-Object { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")}
    } catch {
        if($_.Exception.Message -match "Cannot validate argument on parameter"){
            try {
                $incompleteRun = $true;
                Out-LogFile "We ran into an error retrieving Mailbox Delegates where 'FullAccess' permission is granted. If a report is generated, it may not be complete." -warning;
                Write-Host -ForegroundColor Red "[!] We ran into an error retrieving Mailbox Delegates where 'FullAccess' permission is granted. If a report is generated, it may not be complete.";
                Write-Host -ForegroundColor Yellow "Try using the following command to obtain this report manually:"
                Write-Host -ForegroundColor Yellow 'Get-EXOMailbox -ResultSize Unlimited | Get-EXOMailboxPermission | Where-Object { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")} | Export-Csv "FullAccessPerms.csv" -NoTypeInformation'
            } catch {
                Write-Error $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };
    if($FullAccessPerms.Count -gt 0) {
        foreach ($obj in $FullAccessPerms){
            $ObjectProperties = [Ordered]@{
                Identity = $obj | Select-Object -exp Identity
                User = $obj | Select-Object -exp User
                AccessRights = $obj | Select-Object -exp AccessRights
                IsInherited = $obj | Select-Object -exp IsInherited
                Deny = $obj | Select-Object -exp Deny
                InheritanceType = $obj | Select-Object -exp InheritanceType
            };
            $FullAccessPermsResults += New-Object -TypeName PSObject -Property $ObjectProperties
        };
        try {
            if($incompleteRun) {
                Out-LogFile "While some results returned, this report did not complete successfully. Please try running it manually." -warning;
                Write-Host -ForegroundColor Yellow "[!] While some results returned, this report did not complete successfully. Please try running it manually."
            };
            $FullAccessPermsResults | Export-Csv "$reportsFolder\FullAccessPerms.csv" -NoTypeInformation;
            $FullAccessPermsResults | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\FullAccessPerms.json"
        } catch {
            Out-LogFile "Unable to write output to disk" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
        };
        try {
            Out-LogFile ("[+] Found " + $FullAccessPerms.count + " delegate(s) with 'Full Access' permission");
            Out-LogFile "[+] Review Mailbox Delegates where 'Full Access' permission is granted. Output saved to '$runFolderShort\Reports\FullAccessPerms.csv'";
            Out-Summary "Delegates with 'Full Access' Permission Granted" -NewReport;
            Out-Summary ("[+] Found " + $FullAccessPerms.count + " delegate(s) with 'Full Access' permission");
            Out-Summary "[+] Review Mailbox Delegates where 'Full Access' permission is granted. Output saved to '$runFolderShort\Reports\FullAccessPerms.csv'";
            Out-Summary "`rINVESTIGATIVE TIPS:
            - Check which accounts have 'Full Access' to mailboxes; ideally there should be a limited number of accounts with this access.
            - Typically an email gateway account (e.g., Proofpoint, Barracuda, etc) would have full access." -Summary
        } catch {
            Out-LogFile "There was a problem logging this query" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
        }
    }
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: FullAccessGranted
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: AnyAccessGranted (Mailbox Delegates where "Any" Permissions are Granted)
#
$moduleMessage = "Retrieving Mailbox Delegates where 'Any' permissions are granted";
if ($Commands -and $Commands -notmatch "AnyAccessGranted") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    Write-Host -ForegroundColor Yellow "This make take awhile; please be patient...";
    $AnyAssignedPerms = @();
    $AnyAssignedPermsResults = @();
    try {
        $AnyAssignedPerms += Get-EXOMailbox -ResultSize Unlimited -ErrorAction SilentlyContinue | Get-EXOMailboxPermission -ErrorAction Stop | Where-Object { ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")}
    } catch {
        if($_.Exception.Message -match "Cannot validate argument on parameter"){
            try {
                $incompleteRun = $true;
                Out-LogFile "We ran into an error retrieving Mailbox Delegates where 'Any' permissions are granted. If a report is generated, it may not be complete." -warning;
                Write-Host -ForegroundColor Red "[!] We ran into an error retrieving Mailbox Delegates where 'Any' permissions are granted. If a report is generated, it may not be complete.";
                Write-Host -ForegroundColor Yellow "Try using the following command to obtain this report manually:"
                Write-Host -ForegroundColor Yellow 'Get-EXOMailbox -ResultSize Unlimited | Get-EXOMailboxPermission | Where-Object { ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF")} | Export-Csv "AnyAssignedPerms.csv" -NoTypeInformation'
            } catch {
                Write-Error $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };
    if($AnyAssignedPerms.Count -gt 0) {
        foreach ($obj in $AnyAssignedPerms){
            $ObjectProperties = [Ordered]@{
                Identity = $obj | Select-Object -exp Identity
                User = $obj | Select-Object -exp User
                AccessRights = $obj | Select-Object -exp AccessRights
                IsInherited = $obj | Select-Object -exp IsInherited
                Deny = $obj | Select-Object -exp Deny
                InheritanceType = $obj | Select-Object -exp InheritanceType
            };
            $AnyAssignedPermsResults += New-Object -TypeName PSObject -Property $ObjectProperties
        };
        try {
            if($incompleteRun) {
                Out-LogFile "While some results returned, this report did not complete successfully. Please try running it manually." -warning;
                Write-Host -ForegroundColor Yellow "[!] While some results returned, this report did not complete successfully. Please try running it manually."
            };
            $AnyAssignedPermsResults | Export-Csv "$reportsFolder\AnyAssignedPerms.csv" -NoTypeInformation;
            $AnyAssignedPermsResults | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\AnyAssignedPerms.json"
        } catch {
            Out-LogFile "Unable to write output to disk" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
        };
        try {
            Out-LogFile ("[+] Found " + $AnyAssignedPerms.count + " delegate(s) where 'Any' permissions are granted");
            Out-LogFile "[+] Review Mailbox Delegates with 'Any' permissions. Output saved to '$runFolderShort\Reports\AnyAssignedPerms.csv'";
            Out-Summary "Delegates with 'Any' Permissions Granted" -NewReport;
            Out-Summary ("[+] Found " + $AnyAssignedPerms.count + " delegate(s) where 'Any' permissions are granted");
            Out-Summary "[+] Review Mailbox Delegates with 'Any' permissions. Output saved to '$runFolderShort\Reports\AnyAssignedPerms.csv'";
            Out-Summary "`rINVESTIGATIVE TIPS:
            - Look for any suspicious use of 'personal' like accounts with permissions to mailboxes." -Summary
        } catch {
            Out-LogFile "There was a problem logging this query" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
        }
    }
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: AnyAccessGranted
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: SendAsGranted (Mailbox Delegates where "Send As" or "SendOnBehalf" Permissions are Granted)
#
$moduleMessage = "Retrieving Mailbox Delegates where 'Send As' or 'SendOnBehalf' permission is granted";
if ($Commands -and $Commands -notmatch "SendAsGranted") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    Write-Host -ForegroundColor Yellow "This make take awhile; please be patient...";
    $DelegateSendPerms = @();
    try {
        $DelegateSendPerms += Get-EXOMailbox -ResultSize Unlimited -ErrorAction SilentlyContinue | Get-EXORecipientPermission -ErrorAction Stop | Where-Object {$_.Trustee -ne "NT AUTHORITY\SELF"}    
    } catch {
        if($_.Exception.Message -match "unauthorized"){
            try {
                Out-LogFile "Unable to retrieve Mailbox Delegates where 'Send As' or 'SendOnBehalf' permission is granted. Requires 'Global Admin' role." -warning;
                Write-Host -ForegroundColor Red "[!] Unable to retrieve Mailbox Delegates where 'Send As' or 'SendOnBehalf' permission is granted. Requires 'Global Admin' role. Skipping command..."
            } catch {
                Write-Error $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };
    try {
        $DelegatesSendPerms += Get-EXOMailbox -ResultSize Unlimited | Where-Object {$_.GrantSendOnBehalfTo -ne $null}
    } catch {
        Out-LogFile "Unable to retrieve Mailbox Delegates where where 'Send As' or 'SendOnBehalf' permission is granted" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Mailbox Delegates where where 'Send As' or 'SendOnBehalf' permission is granted"
    };
    if($DelegateSendPerms.Count -gt 0) {
        try {
            $DelegateSendPerms | Export-Csv "$reportsFolder\SendAsDelegates.csv" -NoTypeInformation;
            $DelegateSendPerms | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\SendAsDelegates.json"
        } catch {
            Out-LogFile "Unable to write output to disk" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
        };
        try {
            Out-LogFile ("[+] Found " + $DelegateSendPerms.count + " delegate(s) where 'SendAs' or 'SendOnBehalf permission is granted");
            Out-LogFile "[+] Review Mailbox Delegates where 'Send As' or 'SendOnBehalf' permission is granted. Output saved to '$runFolderShort\Reports\SendAsDelegates.csv'";
            Out-Summary "Delegates with 'Send As' or 'SendOnBehalf' Permissions" -NewReport;
            Out-Summary ("[+] Found " + $DelegateSendPerms.count + " delegate(s) where 'SendAs' or 'SendOnBehalf permission is granted");
            Out-Summary "[+] Review Mailbox Delegates where 'Send As' or 'SendOnBehalf' permission is granted. Output saved to '$runFolderShort\Reports\SendAsDelegates.csv'";
            Out-Summary "`rINVESTIGATIVE TIPS:
            - Look for any suspicious use of 'personal' like accounts with 'Send As' or 'SendOnBehalf' permissions.
            - Threat actors can take advantage for phishing campaigns as trusted users." -Summary
        } catch {
            Out-LogFile "There was a problem logging this query" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
        }
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: SendAsGranted
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: EXOPowerShell (Exchange Online PowerShell Enabled Users)
#
$moduleMessage = "Retrieving Exchange Online PowerShell enabled users";
if ($Commands -and $Commands -notmatch "EXOPowerShell") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $EXOPowerShellUsers = $null;
    try {
        [array]$EXOPowerShellUsers = Get-User -ResultSize unlimited | Select-Object Name,DisplayName,UserPrincipalName,RemotePowerShellEnabled,AccountDisabled;
        if($EXOPowerShellUsers.Count -gt 0) {
            try {
                $EXOPowerShellUsers | Export-Csv -Path "$reportsFolder\EXOPowerShellUsers.csv" -NoTypeInformation;
                $EXOPowerShellUsers | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\EXOPowerShellUsers.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $EXOPowerShellUsers.count + " Exchange Online user(s) with Remote PowerShell enabled");
                Out-LogFile "Review Exchange Online PowerShell enabled users. Output saved to '$runFolderShort\Reports\EXOPowerShellUsers.csv";
                Out-Summary "Exchange Online PowerShell Enabled Users" -NewReport;
                Out-Summary ("[+] Found " + $EXOPowerShellUsers.count + " Exchange Online user(s) with Remote PowerShell enabled");
                Out-Summary "Review Exchange Online PowerShell enabled users. Output saved to '$runFolderShort\Reports\EXOPowerShellUsers.csv";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Look for any account that has Remote PowerShell enabled; attackers will typically use Exchange Online PowerShell to interact or exfiltrate emails out of the account because the activity is not monitored." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Exchange Online PowerShell enabled users" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Exchange Online PowerShell enabled users"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: EXOPowerShell
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: AuditBypassEnabled (Audit Bypass Enabled Exchange Online Users)
# 
$moduleMessage = "Retrieving 'Audit Bypass' enabled Exchange Online users";
if ($Commands -and $Commands -notmatch "AuditBypassEnabled") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    Write-Host -ForegroundColor Yellow "This make take awhile; please be patient...";
    $AuditByPassEnabled = $null;
    try {
        [array]$AuditByPassEnabled = Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object{$_.AuditBypassEnabled -eq $true} | Select-Object Name,AuditBypassEnabled;
        if($AuditByPassEnabled.Count -gt 0) {
            try {
                $AuditByPassEnabled | Export-Csv -Path "$reportsFolder\AuditByPassEnabledUsers.csv" -NoTypeInformation;
                $AuditByPassEnabled | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\AuditByPassEnabledUsers.json"
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $AuditByPassEnabled.count + " Exchange Online user(s) with 'Audit Bypass' enabled");
                Out-LogFile "[+] Review 'Audit Bypass' enabled Exchange Online users. Output saved to '$runFolderShort\Reports\AuditByPassEnabledUsers.csv";
                Out-Summary "Users with 'Audit Bypass' Enabled" -NewReport;
                Out-Summary ("[+] Found " + $AuditByPassEnabled.count + " Exchange Online user(s) with 'Audit Bypass' enabled");
                Out-Summary "[+] Review 'Audit Bypass' enabled Exchange Online users. Output saved to '$runFolderShort\Reports\AuditByPassEnabledUsers.csv";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Look for any account that has 'Audit Bypass' enabled; this option disables monitoring of the respective user account.
                - Threat actors could target these accounts to evade detection - no Unified Search Audit Log events will be generated." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Audit Bypass enabled Exchange Online users" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Audit Bypass enabled Exchange Online users";
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: AuditBypassEnabled
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: HiddenMailboxes (Retrieve Hidden Mailboxes from Exchange Online)
#
$moduleMessage = "Retrieving Hidden Mailboxes from Exchange Online";
if ($Commands -and $Commands -notmatch "HiddenMailboxes") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $HiddenMailboxes = $null;
    try {
        [array]$HiddenMailboxes = Get-EXORecipient -ResultSize Unlimited | Where-Object{$_.HiddenFromAddressListsEnabled -eq $true};
        if($HiddenMailboxes.Count -gt 0) {
            try {
                $HiddenMailboxes | Export-Csv "$reportsFolder\HiddenMailboxes.csv" -NoTypeInformation;
                $HiddenMailboxes | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\HiddenMailboxes.json";
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $HiddenMailboxes.count + " Hidden Mailbox(es)");
                Out-LogFile "[+] Review Hidden Mailboxes from Exchange Online. Output saved to '$runFolderShort\Reports\HiddenMailboxes.csv'";
                Out-Summary "Hidden Mailboxes from Exchange Online" -NewReport;
                Out-Summary ("[+] Found " + $HiddenMailboxes.count + " Hidden Mailbox(es)");
                Out-Summary "[+] Review Hidden Mailboxes from Exchange Online. Output saved to '$runFolderShort\Reports\HiddenMailboxes.csv'";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Look for suspicious mailboxes hidden from the Global Address List (GAL)." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Hidden Mailboxes from Exchange Online" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Hidden Mailboxes from Exchange Online"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: HiddenMailboxes
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: KeyCredentials (Retrieve Service Principal Objects with KeyCredentials)
#
$moduleMessage = "Retrieving Azure AD Service Principal objects";
if ($Commands -and $Commands -notmatch "KeyCredentials") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $ServicePrincipalQuery = $null;
    $ServicePrincipalObjects = @();
    try {
        [array]$ServicePrincipalQuery = Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null};
        if($ServicePrincipalQuery.Count -gt 0) {
            $counter = 0;
            ForEach($obj in $ServicePrincipalQuery) {
                $counter += 1;
                Write-Progress -Activity "Retrieving Service Principal Objects" -Status "In progress" -PercentComplete $(($counter/$ServicePrincipalQuery.Count)*100);
                $KeyCred = $obj | Select-Object -exp KeyCredentials;
                $ObjectProperties = [Ordered]@{
                    "ObjectId" = ($obj.ObjectId | Out-String).Trim()
                    "AppId" = ($obj.AppId | Out-String).Trim()
                    "StartDate" = ($KeyCred.StartDate | Out-String).Trim()
                    "EndDate" = ($KeyCred.EndDate | Out-String).Trim()
                    "KeyId" = ($KeyCred.KeyId | Out-String).Trim()
                    "Type" = ($KeyCred.Type | Out-String).Trim()
                    "Usage" = ($KeyCred.Usage | Out-String).Trim()
                };
                $ServicePrincipalObjects += New-Object -TypeName PSObject -Property $ObjectProperties
            }
        };
        if($ServicePrincipalObjects.Count -gt 0) {
            try {
                $ServicePrincipalObjects | Export-Csv -Path "$reportsFolder\ServicePrincipalObjects.csv" -NoTypeInformation;
                $ServicePrincipalObjects | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\ServicePrincipalObjects.json";
            } catch {
                Out-LogFile "Unable to write output to disk" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
            };
            try {
                Out-LogFile ("[+] Found " + $ServicePrincipalObjects.count + " Service Principal objects for review");
                Out-LogFile "[+] Review 'Service Principal with KeyCredentials' objects. Output saved to '$runFolderShort\Reports\ServicePrincipalObjects.csv";
                Out-Summary "Service Principal Objects with KeyCredentials" -NewReport;
                Out-Summary ("[+] Found " + $ServicePrincipalObjects.count + " Service Principal objects for review");
                Out-Summary "[+] Review 'Service Principal' objects. Output saved to '$runFolderShort\Reports\ServicePrincipalObjects.csv";
                Out-Summary "`rINVESTIGATIVE TIPS:
                - Threat Actors can create or replace credentials on service principals to act as that principal to evade detection.
                - NOTE: This is a known SUNBURST TTP." -Summary
            } catch {
                Out-LogFile "There was a problem logging this query" -warning;
                Write-Error $_.Exception.Message;
                Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
            }
        }
    } catch {
        Out-LogFile "Unable to retrieve Service Principal objects" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to retrieve Service Principal";
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    };
}
#
# End Command: KeyCredentials
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: O365AdminGroups (Retrieve Service Principal Objects with KeyCredentials)
#
$moduleMessage = "Retrieving O365 admin roles";
if ($Commands -and $Commands -notmatch "O365AdminGroups") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $O365AdminGroupReport = New-Object System.Collections.ArrayList;
    $now = Get-Date;
    $ShortDate = $now.ToShortDateString() -replace "/","";

    $OutputFileName = "Office365AdminGroupMembers.csv";

    #Get the Azure AD roles for the tenant
    try {
        $AzureADRoles = @(Get-AzureADDirectoryRole -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -ieq "You must call the Connect-AzureAD cmdlet before calling any other cmdlets.") {
            #Connect to Azure AD
            try {
                $AzureADConnection = Connect-AzureAD -ErrorAction Stop 6>$null;
                $AzureADRoles = @(Get-AzureADDirectoryRole -ErrorAction Stop)
            } catch {
                throw $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };

    #Loop through the Azure AD roles
    foreach ($AzureADRole in $AzureADRoles) {

        Out-LogFile "Processing $($AzureADRole.DisplayName)"

        #Get the list of members for the role
        $RoleMembers = @(Get-AzureADDirectoryRoleMember -ObjectId $AzureADRole.ObjectId)

        #Loop through the list of members
        $counter = 0;
        foreach ($RoleMember in $RoleMembers) {
            Write-Progress -Activity "Getting Azure AD members" -Status "In progress" -PercentComplete $(($counter/$RoleMembers.Count)*100);
            $ObjectProperties = [Ordered]@{
                "Role" = $AzureADRole.DisplayName
                "Display Name" = $RoleMember.DisplayName
                "Object Type" = $RoleMember.ObjectType
                "Account Enabled" = $RoleMember.AccountEnabled
                "User Principal Name" = $RoleMember.UserPrincipalName
                "Password Policies" = $RoleMember.PasswordPolicies
                "HomePage" = $RoleMember.HomePage
            }

            $RoleMemberObject = New-Object -TypeName PSObject -Property $ObjectProperties

            #Add the role member's details to the array for the report data
            [void]$O365AdminGroupReport.Add($RoleMemberObject)
        }
    };

    #Output the report to CSV
    if ($null -ne $O365AdminGroupReport) {
        try {
            $O365AdminGroupReport | Export-CSV -Path "$reportsFolder\$OutputFileName" -Force -NoTypeInformation;
            $O365AdminGroupReport | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\$($OutputFileName.Replace(".csv",".json"))";
        } catch {
            Out-LogFile "Unable to write output to disk" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
        };
        try {
            Out-LogFile ("[+] Found " + $O365AdminGroupReport.count + " O365 admin role members");
            Out-LogFile "[+] Saving O365 Admin Groups report to the path: '$runFolderShort\Reports\$OutputFileName'";
            Out-Summary "O365 Admin Groups Report" -NewReport;
            Out-Summary ("[+] Found " + $O365AdminGroupReport.count + " O365 admin role members");
            Out-Summary "[+] Saving O365 Admin Groups report to the path: '$runFolderShort\Reports\$OutputFileName'";
            Out-Summary "`rINVESTIGATIVE TIPS:
            - Review all members of admin groups.
            - Members assigned with the 'ApplicationImpersonation' role can impersonate any account in the tenant.
            - Threat Actors can target these accounts for elevated privileges & to gain access to contents." -Summary
        } catch {
            Out-LogFile "There was a problem logging this query" -warning;
            Write-Error $_.Exception.Message;
            Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
        }
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: O365AdminGroups
#............................................................................................................................................

#............................................................................................................................................
# Begin Command: DelegateAppPerms (Retrieve Delegate and Application Related Permissions)
#
$moduleMessage = "Retrieving Delegate Application Permissions";
if ($Commands -and $Commands -notmatch "DelegateAppPerms") {
    $continue = $false
} elseif ($Interactive) {
    Out-LogFile $moduleMessage;
    $startTimer = [System.Diagnostics.Stopwatch]::StartNew();
    Write-Host $InteractiveMessage;
    $skip = $null;
    $continue = $null;
    do {
        if ($startTimer.Elapsed.Seconds -gt $InteractiveWaitSeconds) {
            $continue = $true
        }
        if ([Console]::KeyAvailable) {
            $keyPress = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            if ($keyPress) {
                $skip = $true
            }
        }
    } while((-not $skip) -and (-not $continue))
} else {
    $continue = $true
};

if ($continue) {
    if (-not $Interactive) {
        Out-LogFile $moduleMessage
    }
    if ($Interactive) {
        Write-Host $InteractiveContMessage
    };
    $ADPSOutputFileName = "AzureADPSPermissionsReport.csv";
    # Get tenant details to test that Connect-AzureAD has been called
    try {
        $tenant_details = Get-AzureADTenantDetail
    } catch {
        Out-LogFile "You must call Connect-AzureAD before running this script." -warning
    };
    Out-LogFile ("TenantId: {0}, InitialDomain: {1}" -f `
                    $tenant_details.ObjectId, `
                    ($tenant_details.VerifiedDomains | Where-Object { $_.Initial }).Name)

    # An in-memory cache of objects by {object ID} andy by {object class, object ID}
    $script:ObjectByObjectId = @{};
    $script:ObjectByObjectClassId = @{};

    $data = @();
    $empty = @{} # Used later to avoid null checks

    # Get all ServicePrincipal objects and add to the cache
    Out-LogFile "Retrieving all ServicePrincipal objects...";
    Get-AzureADServicePrincipal -All $true | ForEach-Object {
        CacheObject -Object $_
    };
    $servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count

    # Get one page of User objects and add to the cache
    Out-LogFile ("Retrieving up to {0} User objects..." -f 999)
    Get-AzureADUser -Top 999 | Where-Object {
        CacheObject -Object $_
    };

    Out-LogFile "Testing for OAuth2PermissionGrants bug before querying...";
    $fastQueryMode = $false;

    try {
        # There's a bug in Azure AD Graph which does not allow for directly listing
        # oauth2PermissionGrants if there are more than 999 of them. The following line will
        # trigger this bug (if it still exists) and throw an exception.
        $null = Get-AzureADOAuth2PermissionGrant -Top 999;
        $fastQueryMode = $true
    } catch {
        if ($_.Exception.Message -and $_.Exception.Message.StartsWith("Unexpected end when deserializing array.")) {
            Out-LogFile ("Fast query for delegated permissions failed, using slow method...")
        } else {
            throw $_
        }
    };

    # Get all existing OAuth2 permission grants, get the client, resource and scope details
    Out-LogFile "Retrieving OAuth2PermissionGrants...";

    GetOAuth2PermissionGrants -FastMode:$fastQueryMode | ForEach-Object {
        $grant = $_;
        if ($grant.Scope) {
            $grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {

                $scope = $_;

                $grantDetails =  [ordered]@{
                    "PermissionType" = "Delegated"
                    "ClientObjectId" = $grant.ClientId
                    "ResourceObjectId" = $grant.ResourceId
                    "Permission" = $scope
                    "ConsentType" = $grant.ConsentType
                    "PrincipalObjectId" = $grant.PrincipalId
                };

                # Add properties for client and resource service principals
                $ServicePrincipalProperties = @("DisplayName", "AppId");
                if ($ServicePrincipalProperties.Count -gt 0) {

                    $client = GetObjectByObjectId -ObjectId $grant.ClientId;
                    $resource = GetObjectByObjectId -ObjectId $grant.ResourceId;

                    $insertAtClient = 2;
                    $insertAtResource = 3;
                    foreach ($propertyName in $ServicePrincipalProperties) {
                        $grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName);
                        $insertAtResource++;
                        $grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName);
                        $insertAtResource ++
                    }
                };

                # Add properties for principal (will all be null if there's no principal)
                $UserProperties = @("DisplayName", "UserPrincipalName", "Mail");
                if ($UserProperties.Count -gt 0) {

                    $principal = $empty
                    if ($grant.PrincipalId) {
                        $principal = GetObjectByObjectId -ObjectId $grant.PrincipalId
                    }

                    foreach ($propertyName in $UserProperties) {
                        $grantDetails["Principal$propertyName"] = $principal.$propertyName
                    }
                };

                $data += New-Object PSObject -Property $grantDetails
            }
        }
    }

    # Iterate over all ServicePrincipal objects and get app permissions
    Out-LogFile "Retrieving AppRoleAssignments...";
    Write-Host -ForegroundColor Yellow "This make take awhile; please be patient...";

    $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {

        if (-not($ShowProgress)) {
            Write-Progress -Activity "Retrieving application permissions..." `
                        -Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
                        -PercentComplete (($i / $servicePrincipalCount) * 100)
        };

        $sp = $_.Value;

        Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true `
        | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {
            $assignment = $_;

            $resource = GetObjectByObjectId -ObjectId $assignment.ResourceId;
            $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id };

            $grantDetails = [ordered]@{
                "PermissionType" = "Application"
                "ClientObjectId" = $assignment.PrincipalId
                "ResourceObjectId" = $assignment.ResourceId
                "Permission" = $appRole.Value
            };

            # Add properties for client and resource service principals
            if ($ServicePrincipalProperties.Count -gt 0) {

                $client = GetObjectByObjectId -ObjectId $assignment.PrincipalId;

                $insertAtClient = 2;
                $insertAtResource = 3;
                foreach ($propertyName in $ServicePrincipalProperties) {
                    $grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName);
                    $insertAtResource++;
                    $grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName);
                    $insertAtResource ++
                }
            };

            $data += New-Object PSObject -Property $grantDetails
        }
    };
    try {
        $data | Export-CSV -Path "$reportsFolder\$ADPSOutputFileName" -Force -NoTypeInformation;
        $data | ConvertTo-Json -Depth 10 | Out-File "$jsonFolder\$($ADPSOutputFileName.Replace(".csv",".json"))"
    } catch {
        Out-LogFile "Unable to write output to disk" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] Unable to write output to disk"
    };
    try {
        Out-LogFile ("[+] Found " + $data.count + " Delegated/Application Permissions");
        Out-LogFile "[+] Saving AzureADPSPermissions Report to the path: '$runFolderShort\Reports\$ADPSOutputFileName'";
        Out-Summary "Delegated Permissions & Application Permissions" -NewReport;
        Out-Summary ("[+] Found " + $data.count + " Delegated/Application Permissions");
        Out-Summary "[+] Saving AzureADPSPermissions Report to the path: '$runFolderShort\Reports\$ADPSOutputFileName'";
        Out-Summary "`rINVESTIGATIVE TIPS:
        - Look for overly permissive and suspicious apps.
        - Any suspicious apps identified should have authentication activity reviewed.
        - Threat Actors can add permissions to these Azure AD apps for long-term lowered visibility access to contacts, mail, notes, mailbox settings, user directory, and files.
        - NOTE: This is a known SUNBURST TTP." -Summary
    } catch {
        Out-LogFile "There was a problem logging this query" -warning;
        Write-Error $_.Exception.Message;
        Write-Host -ForegroundColor Red "[!] There was a problem logging this query"
    };
} else {
    if ($Interactive) {
        Write-Host $InteractiveSkipMessage
    }
};
#
# End Command: DelegateAppPerms
#............................................................................................................................................


# Disconnect from Exchange Online and Azure AD
try {
    Disconnect-ExchangeOnline -Confirm:$false 6>$null;
    Out-LogFile "Disconnected from Exchange Online";
    Disconnect-AzureAD | Out-Null;
    Out-LogFile "Disconnected from Azure AD"
} catch {
    Write-Error $_.Exception.Message
}