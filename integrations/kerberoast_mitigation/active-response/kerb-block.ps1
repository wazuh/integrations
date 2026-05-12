###########################################################################
# WILLIAMS MITIGATION FRAMEWORK (WMF) - Version 1.0
# Author: R-Williams-Security
# Official Integration: Wazuh PR #75 (Merged)
# License: GNU AGPLv3
# Description: Automated Active Response for Kerberoasting (T1558.003)
# Dedicated to the Wazuh Open Source Community.
###########################################################################
# kerb-block.ps1
# Wazuh Active Response script - receives alert via stdin, disables the targeted AD account

$logPath = "C:\Security\SOAR.log"

# Ensure log directory exists before any writes
if (-not (Test-Path "C:\Security")) {
    New-Item -ItemType Directory -Path "C:\Security" -Force | Out-Null
}

try {
    # Wazuh passes the alert JSON to the script via standard input (stdin)
    $inputData = $null
    $inputData = [Console]::In.ReadToEnd()

    if ([string]::IsNullOrWhiteSpace($inputData)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: No input received from Wazuh" |
            Out-File -FilePath $logPath -Append
        exit 1
    }

    # Parse the JSON alert with dedicated error handling for malformed input
    try {
        $alert = $inputData | ConvertFrom-Json
    }
    catch {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Failed to parse alert JSON. Raw input: $inputData" |
            Out-File -FilePath $logPath -Append
        exit 1
    }

    # Check the Wazuh active-response command field (add / delete)
    # Only perform the disable action for the 'add' command
    $command = $alert.command
    if ([string]::IsNullOrWhiteSpace($command)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: No command field in Wazuh active-response payload" |
            Out-File -FilePath $logPath -Append
        exit 1
    }
    if ($command -ne 'add') {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - INFO: Ignoring command '$command' - no account action taken" |
            Out-File -FilePath $logPath -Append
        exit 0
    }

    # Extract the targeted service account from the alert data
    $targetAccount = $alert.data.win.eventdata.targetUserName

    if ([string]::IsNullOrWhiteSpace($targetAccount)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Could not extract target account from alert JSON" |
            Out-File -FilePath $logPath -Append
        exit 1
    }

    # Import Active Directory module (requires RSAT on the Domain Controller)
    Import-Module ActiveDirectory -ErrorAction Stop

    # Disable the compromised service account
    Disable-ADAccount -Identity $targetAccount -ErrorAction Stop

    # Write success audit entry to SOAR log
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SUCCESS: Disabled account: $targetAccount" |
        Out-File -FilePath $logPath -Append

    exit 0
}
catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $($_.Exception.Message)" |
        Out-File -FilePath $logPath -Append
    exit 1
}
