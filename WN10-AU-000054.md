# STIG Remediation — WN10-AU-000054
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control enables auditing for **Account Lockout** events so Windows records when user accounts are locked due to repeated failed logon attempts.

**STIG Requirement**
> The system must be configured to audit Account Lockout events.

---

## Why This Matters

Account lockouts can indicate:

- Brute-force or password-spraying activity
- Compromised devices repeatedly attempting authentication
- Misconfigured services or stale cached credentials

Enabling this audit provides evidence for investigations and supports detection workflows.

---

## Technical Details

- **STIG ID:** WN10-AU-000054
- **Audit Policy Subcategory:** `Account Lockout`
- **Required Setting:** Success and Failure enabled

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Enables auditing for Account Lockout events (Success and Failure) to meet STIG WN10-AU-000054.

.NOTES
    Author          : Chau Pham
    LinkedIn        : linkedin.com/in/chaupham01/
    GitHub          : github.com/ChauPham-Security
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-AU-000054

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-AU-000054-AuditAccountLockout.ps1
#>

$subcategory = "Account Lockout"

try {
    # Apply the audit policy - enable Failure auditing
    $result = auditpol /set /subcategory:"$subcategory" /failure:enable

    if ($LASTEXITCODE -eq 0) {
        Write-Output "SUCCESS: Audit policy for '$subcategory' set to include Failure."
    } else {
        Write-Output "ERROR: auditpol command failed. Exit code: $LASTEXITCODE"
        exit 1
    }

    # Verify the setting was applied
    $verify = auditpol /get /subcategory:"$subcategory"
    Write-Output "`nVerification output:"
    $verify | ForEach-Object { Write-Output $_ }

    # Check that Failure is present in the output
    if ($verify -match "Failure") {
        Write-Output "`nSUCCESS: Failure auditing confirmed for '$subcategory'."
        exit 0
    } else {
        Write-Output "`nERROR: Failure auditing NOT detected in verification output."
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
