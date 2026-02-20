# STIG Remediation — WN10-AC-000030  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control enforces a minimum password age of **at least 1 day** to prevent users from repeatedly changing passwords to bypass password history restrictions.

**STIG Requirement**

> The minimum password age must be configured to 1 day or greater.

---

## Why This Matters

If the minimum password age is set to 0:

- Users can immediately change their password again
- Password history controls can be bypassed
- Old passwords can be reused quickly

Setting a minimum password age of 1 day:

- Prevents rapid password cycling  
- Reinforces password history enforcement  
- Strengthens authentication policy integrity  

This control works in conjunction with password history and complexity requirements.

---

## Technical Details

- **STIG ID:** WN10-AC-000030  
- **Policy Name:** Minimum Password Age  
- **Required Setting:** 1 day or greater  
- **Configuration Tool:** Local Security Policy / `net accounts`  

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Configures Minimum Password Age to 1 day
    to meet STIG WN10-AC-000030.

.NOTES
    Author          : Chau Pham
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-AC-000030

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-AC-000030-MinPasswordAge.ps1
#>

try {
    Write-Output "Setting Minimum Password Age to 1 day..."

    # Configure minimum password age
    net accounts /minpwage:1 | Out-Null

    # Retrieve current account policy settings
    $output = net accounts

    Write-Output "Verification Output:"
    Write-Output $output

    # Validate configuration
    if ($output -match "Minimum password age \(days\):\s+1") {
        Write-Output "SUCCESS: Minimum password age is set to 1 day."
        exit 0
    }
    else {
        Write-Output "ERROR: Minimum password age is not correctly configured."
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
