# windows-security-hardening-lab

# Windows Security Hardening & Vulnerability Remediation Lab

## Objective
This repository demonstrates a structured security improvement workflow on a Windows 10 VM by completing:

- **Program 1:** Remediate and automate **10 DISA Windows 10 STIG V3R1** controls
- **Program 2:** Remediate and validate **10 vulnerability findings** identified through scanning

The goal is to simulate an enterprise-style remediation lifecycle (baseline → fix → validate → document → automate), not isolated lab tweaks.

---

## Environment
- **Target:** Azure Windows 10 Virtual Machine
- **Scanning:** Tenable.io (Compliance + Vulnerability scanning)
- **STIG Standard:** **Microsoft Windows 10 STIG V3R1**
- **Automation:** PowerShell (native on Windows 10)

---

## Methodology (Lifecycle Used)
For each STIG control or vulnerability finding:

1. **Baseline scan** to capture failure state
2. **Select a finding** and identify the control/finding ID
3. **Research remediation guidance**
4. **Apply manual fix** and document steps
5. **Rescan** to confirm remediation success
6. **Revert** the change (when feasible) and rescan to confirm detection
7. **Automate remediation** using PowerShell (idempotent)
8. **Rescan** to confirm automated success
9. **Document evidence** (before/after)

---

## Repository Structure
```text
.
├── README.md
├── stig-remediation/
│   ├── baseline/
│   │   ├── baseline-scan-summary.md
│   │   └── baseline-scan-results.png
│   ├── controls/
│   │   ├── WN10-AU-000500/
│   │   │   ├── README.md
│   │   │   ├── detection.ps1
│   │   │   ├── remediation.ps1
│   │   │   ├── before.png
│   │   │   └── after.png
│   │   └── ... (9 more controls)
│   └── summary.md
│
└── vulnerability-remediation/
    ├── baseline/
    │   ├── baseline-scan-summary.md
    │   └── baseline-scan-results.png
    ├── findings/
    │   ├── FINDING-001/
    │   │   ├── README.md
    │   │   ├── remediation.ps1   (optional)
    │   │   ├── before.png
    │   │   └── after.png
    │   └── ... (9 more findings)
    └── summary.md
