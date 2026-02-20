# STIG Remediation — WN10-UR-000070  
**Microsoft Windows 10 STIG V3R1**

---

## Overview

This control restricts which users and groups are permitted to log on through Remote Desktop Services (RDP).

**STIG Requirement**

> Only authorized accounts (typically Administrators and Remote Desktop Users) must be allowed to log on through Remote Desktop Services.

---

## Why This Matters

If Remote Desktop access is not restricted:

- Attackers can gain interactive remote access
- Lateral movement becomes easier
- Brute-force attacks against RDP are more effective
- Privileged accounts may be exposed remotely

Restricting RDP access enforces least privilege and reduces attack surface.

---

## Technical Details

- **STIG ID:** WN10-UR-000070  
- **User Right:** `SeRemoteInteractiveLogonRight`  
- **Required Configuration:**  
  - Administrators  
  - Remote Desktop Users  

---

## Remediation Script

```powershell
<#
.SYNOPSIS
    Restricts "Allow log on through Remote Desktop Services"
    to Administrators and Remote Desktop Users
    to meet STIG WN10-UR-000070.

.NOTES
    Author          : Chau Pham
    Date Created    : 2026-02-20
    Version         : 1.0
    STIG-ID         : WN10-UR-000070

.USAGE
    Run as Administrator:
    PS C:\> .\remediate-WN10-UR-000070-RDPRestriction.ps1
#>

$tempFile = "$env:TEMP\secpol.cfg"

try {
    Write-Output "Exporting current security policy..."
    secedit /export /cfg $tempFile | Out-Null

    $content = Get-Content $tempFile

    # Replace SeRemoteInteractiveLogonRight entry
    $newLine = "SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555"

    if ($content -match "SeRemoteInteractiveLogonRight") {
        $content = $content -replace "SeRemoteInteractiveLogonRight.*", $newLine
    } else {
        $content += $newLine
    }

    Set-Content -Path $tempFile -Value $content

    Write-Output "Applying updated security policy..."
    secedit /configure /db secedit.sdb /cfg $tempFile /areas USER_RIGHTS | Out-Null

    Write-Output "SUCCESS: Remote Desktop logon rights restricted."
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
