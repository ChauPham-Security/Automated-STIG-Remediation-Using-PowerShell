# STIG Remediation — WN10-AU-000583  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control ensures that failed **Handle Manipulation** attempts are audited to provide visibility into unauthorized object access activity.

**STIG Requirement**

> The system must audit Handle Manipulation failures.

---

## What This Means (Simple Explanation)

In Windows, a *handle* is a reference to a system object such as:

- Files  
- Registry keys  
- Processes  
- Security tokens  

When a program attempts to access or manipulate one of these objects and fails, the system must log the event.

---

## Why This Matters

Failed handle manipulation events may indicate:

- Privilege escalation attempts  
- Token abuse  
- Process injection behavior  
- Unauthorized access to protected objects  

Enabling this audit setting improves detection of low-level attack activity and strengthens forensic capability.

---

## Technical Details

- **STIG ID:** WN10-AU-000583  
- **Audit Policy Subcategory:** `Handle Manipulation`  
- **Required Setting:** Failure enabled  
- **Configuration Tool:** `auditpol`

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Enables auditing for Handle Manipulation (Failure)
    to meet STIG WN10-AU-000583.

.NOTES
    Author          : Chau Pham
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-AU-000583

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-AU-000583.ps1
#>

$subcategory = "Handle Manipulation"

try {
    Write-Output "Enabling Failure auditing for '$subcategory'..."

    # Enable Failure auditing
    auditpol /set /subcategory:"$subcategory" /failure:enable | Out-Null

    # Verify configuration
    $result = auditpol /get /subcategory:"$subcategory"

    Write-Output "Verification Output:"
    Write-Output $result

    if ($result -match "Failure") {
        Write-Output "SUCCESS: Failure auditing is enabled for '$subcategory'."
        exit 0
    }
    else {
        Write-Output "ERROR: Failure auditing is NOT enabled for '$subcategory'."
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
