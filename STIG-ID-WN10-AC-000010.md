# STIG Remediation — WN10-AC-000010  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control enforces an account lockout threshold of **3 or fewer invalid logon attempts** to reduce the effectiveness of brute-force and password spraying attacks.

**STIG Requirement**

> The system must be configured to lock accounts after 3 or fewer unsuccessful logon attempts.

---

## Why This Matters

Without an account lockout threshold:

- Attackers can attempt unlimited password guesses  
- Brute-force attacks become easier  
- Password spraying attempts may go unnoticed  

Setting the threshold to 3:

- Slows password guessing attacks  
- Forces lockout after repeated failures  
- Generates useful lockout audit events  
- Strengthens authentication controls  

This control complements audit logging such as WN10-AU-000054 (Account Lockout auditing).

---

## Technical Details

- **STIG ID:** WN10-AC-000010  
- **Policy Name:** Account Lockout Threshold  
- **Required Setting:** 3 or fewer invalid attempts  
- **Configuration Tool:** Local Security Policy / `net accounts`  

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Configures Account Lockout Threshold to 3 invalid logon attempts
    to meet STIG WN10-AC-000010.

.NOTES
    Author          : Chau Pham
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-AC-000010

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-AC-000010-LockoutThreshold.ps1
#>

try {
    Write-Output "Setting Account Lockout Threshold to 3 invalid attempts..."

    # Configure lockout threshold
    net accounts /lockoutthreshold:3 | Out-Null

    # Retrieve current account policy settings
    $output = net accounts

    Write-Output "Verification Output:"
    Write-Output $output

    # Validate configuration
    if ($output -match "Lockout threshold:\s+3") {
        Write-Output "SUCCESS: Account lockout threshold is set to 3 attempts."
        exit 0
    }
    else {
        Write-Output "ERROR: Account lockout threshold is not correctly configured."
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
