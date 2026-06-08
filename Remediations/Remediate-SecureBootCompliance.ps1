<#
.SYNOPSIS
    Intune Remediation Script - Secure Boot compliance (guidance only)
.DESCRIPTION
    Secure Boot non-compliance generally CANNOT be remediated from the OS:
    - Enabling Secure Boot requires firmware changes (UEFI menu / vendor tool).
    - Switching from legacy BIOS to UEFI requires disk conversion (MBR2GPT)
      AND firmware mode change — too risky to automate without inventory and
      user notification.
    - Enrolling Platform/KEK/DB keys is a firmware operation.

    This script therefore performs NO destructive actions. It logs the
    non-compliance reasons and exits 1 so the device stays flagged for
    manual / fleet-level remediation (e.g. firmware update via vendor tool,
    MBR2GPT campaign, BIOS configuration profile through Dell/HP/Lenovo
    management).

    The companion repository https://github.com/robgrame/* contains a
    SEPARATE script for the Microsoft 2023 Secure Boot certificate rollout
    (registry-based, safe) — use that instead when only that specific
    rollout is missing.

    Exit codes:
        0 = nothing required (shouldn't normally be reached)
        1 = manual remediation required
#>

try {
    # Re-run a minimal detection to log current state
    $sbEnabled = $false
    try { $sbEnabled = [bool](Confirm-SecureBootUEFI) } catch { }

    $firmware = 'Unknown'
    try { $firmware = "$((Get-ComputerInfo -Property BiosFirmwareType).BiosFirmwareType)" } catch { }

    Write-Output "Secure Boot state: Firmware=$firmware, SecureBootEnabled=$sbEnabled"
    Write-Output "Secure Boot non-compliance cannot be safely remediated from the OS."
    Write-Output "Required manual actions (one of):"
    Write-Output " - Enable Secure Boot in the UEFI firmware menu."
    Write-Output " - Convert legacy BIOS systems to UEFI (MBR2GPT + firmware switch)."
    Write-Output " - Apply a vendor BIOS configuration profile (Dell Command, HP CMSL, Lenovo BCU)."
    Write-Output " - For Microsoft 2023 Secure Boot certificate rollout use the dedicated"
    Write-Output "   Detect/Remediate-SecureBootCertUpdate scripts."
    exit 1
}
catch {
    Write-Output "Remediation error: $($_.Exception.Message)"
    exit 1
}
