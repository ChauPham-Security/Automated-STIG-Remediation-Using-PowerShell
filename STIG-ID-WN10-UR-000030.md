# STIG Remediation — WN10-UR-000030  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control ensures that the **Guests group** is denied the ability to log on locally at the system console.

**STIG Requirement**

> The “Deny log on locally” user right must include the Guests group.

---

## What This Means (Simple Explanation)

“Log on locally” means logging in directly at the computer using the Windows login screen.

This control ensures that accounts in the **Guests group** cannot log in interactively at the machine.

---

## Why This Matters

The Guests group is intended for low-trust or temporary accounts.

If Guests are allowed to log in locally:

- Unauthorized users could gain physical access
- Temporary accounts could be misused
- Least privilege principles would be weakened

Denying local logon to Guests:

- Prevents interactive access
- Reduces physical access risk
- Strengthens endpoint access control

---

## Technical Details

- **STIG ID:** WN10-UR-000030  
- **User Right:** `SeDenyInteractiveLogonRight`  
- **Required Group:** Guests  
- **Guests SID:** `S-1-5-32-546`

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Remediates STIG WN10-UR-000030
    "Allow log on locally" must only be assigned to authorized accounts.

.DESCRIPTION
    Configures the SeInteractiveLogonRight to include only
    Administrators (and Users if required by your organization's policy).
    Adjust $AuthorizedAccounts to match your environment.

.NOTES
    Author          : Chau Pham
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-UR-000030

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-UR-000030-DenyLocalLogonGuests.ps1

#>

# Define authorized accounts (SIDs or names)
# Default STIG-compliant: Administrators only
# Adjust as needed (e.g., add "Users" if required by mission need)
$AuthorizedAccounts = @(
    "*S-1-5-32-544"   # Builtin\Administrators
    # "*S-1-5-32-545" # Builtin\Users  (add if operationally required)
)

# Export current security policy
$TempInf = "$env:TEMP\secpol_export.inf"
$TempDb  = "$env:TEMP\secpol.sdb"

secedit /export /cfg $TempInf /quiet

# Read the file
$content = Get-Content $TempInf

# Build the new right assignment
$newRight = "SeInteractiveLogonRight = " + ($AuthorizedAccounts -join ",")

# Replace or add the setting
$updated = $content -replace "^SeInteractiveLogonRight\s*=.*", $newRight

if ($updated -notmatch "SeInteractiveLogonRight") {
    # Setting not present, add it under [Privilege Rights]
    $updated = $updated -replace "(\[Privilege Rights\])", "`$1`n$newRight"
}

# Write updated policy
$updated | Set-Content $TempInf -Encoding Unicode

# Apply the updated policy
secedit /configure /db $TempDb /cfg $TempInf /areas USER_RIGHTS /quiet

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: WN10-UR-000030 remediated." -ForegroundColor Green
} else {
    Write-Host "ERROR: secedit returned exit code $LASTEXITCODE" -ForegroundColor Red
}

# Cleanup
Remove-Item $TempInf, $TempDb -Force -ErrorAction SilentlyContinue
