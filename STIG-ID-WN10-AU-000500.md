# STIG Remediation — WN10-AU-000500  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This remediation enforces the required maximum size for the Windows **Application Event Log** to ensure sufficient log retention for security monitoring and forensic analysis.

STIG Requirement:
> The Windows Application event log size must be configured to 32768 KB (32 MB) or greater.

---

## Why This Matters

If the Application event log size is too small:

- Security events may overwrite before review
- Incident investigations may lack evidence
- Compliance monitoring becomes unreliable
- Audit retention requirements may not be met

Increasing log capacity improves:
- Detection visibility
- Forensic readiness
- Governance reporting accuracy

---

## Technical Details

- **STIG ID:** WN10-AU-000500  
- **Registry Path:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application`  
- **Registry Key:** `MaxSize`  
- **Required Value:** `32768 KB (0x8000)`  
- **Type:** DWORD  

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Ensures the Windows Application event log maximum size is set to at least 32768 KB (32 MB).

.NOTES
    Author          : Chau Pham
    LinkedIn        : linkedin.com/in/chaupham01/
    GitHub          : github.com/ChauPham-Security
    Date Created    : 2026-02-19
    Version         : 1.0
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Windows 10
    PowerShell 5.1+

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-AU-000500-ApplicationLogMaxSize.ps1
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$propertyName = "MaxSize"
$value = 0x8000  # 32768 KB (32 MB)

try {
    # Create registry path if it does not exist
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Create or update the DWORD value
    New-ItemProperty `
        -Path $regPath `
        -Name $propertyName `
        -Value $value `
        -PropertyType DWord `
        -Force | Out-Null

    # Verify configuration
    $currentValue = (Get-ItemProperty -Path $regPath -Name $propertyName).$propertyName

    if ($currentValue -ge $value) {
        Write-Output "SUCCESS: Application Event Log MaxSize set to $currentValue KB."
        exit 0
    }
    else {
        Write-Output "ERROR: Verification failed. Current value is $currentValue KB."
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
