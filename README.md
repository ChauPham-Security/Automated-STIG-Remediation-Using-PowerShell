
## Automated STIG Remediation Using PowerShell

---

## Objective

This repository documents and automates remediation for **10 DISA Microsoft Windows 10 STIG V3R1 controls** on a Windows 10 virtual machine hosted in Azure.

The goal is to demonstrate a practical STIG hardening workflow:

- Select relevant STIG controls
- Implement secure configuration changes
- Automate remediation using PowerShell
- Document what was changed and why

This project focuses strictly on **STIG-based system hardening** (configuration compliance), not general vulnerability remediation.

---

## Scope

This project includes:

- Remediation of **10 Windows 10 STIG V3R1 controls**
- **PowerShell scripts** that implement each control
- **Documentation per control** (requirement + remediation approach + how to confirm the setting)

Each STIG control is delivered as a repeatable, script-based remediation.

---

## Environment

- **Target System:** Azure Windows 10 Virtual Machine  
- **Compliance Standard:** Microsoft Windows 10 STIG V3R1  
- **Automation Tooling:** PowerShell  

---

## Project Structure

Each STIG control includes:

- STIG ID (example: `WN10-AU-000500`)
- Brief requirement summary
- Remediation script (PowerShell)
- Validation command(s) to confirm the setting is applied

---
