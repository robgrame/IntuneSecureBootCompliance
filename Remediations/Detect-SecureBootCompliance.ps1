<#
.SYNOPSIS
    Intune Detection Script - Secure Boot compliance with diagnostic detail
.DESCRIPTION
    Evaluates Secure Boot configuration on the device and emits a structured
    diagnostic record so that the "Pre-remediation detection output" column
    in the Intune Remediations report shows WHY a device is non compliant.

    Criteria evaluated (all configurable below):
    1. Firmware type is UEFI (legacy BIOS = non-compliant)
    2. Secure Boot is enabled (Confirm-SecureBootUEFI -eq $true)
    3. Platform is NOT in Setup Mode (SetupMode UEFI variable = 0)
    4. Microsoft Windows Production PCA 2011 cert present in active DB
    5. (optional) Windows UEFI CA 2023 cert present in active DB
    6. (optional) TPM ready (paired with Secure Boot for full chain of trust)

    Output:
    - Human-readable diagnostic lines
    - A single machine-parsable line:  SECUREBOOT_DIAG={...json...}

    Exit codes:
        0 = Compliant
        1 = Non-compliant (triggers remediation)

    On unexpected error the script exits 0 to avoid false positives.
#>

#region Configuration
$RequireUefiFirmware     = $true
$RequireSecureBootOn     = $true
$RequireNotInSetupMode   = $true
$RequireMsProductionCa   = $true
$RequireUefiCa2023       = $false   # set $true after 2023 cert rollout
$RequireTpmReady         = $true
#endregion

#region Helpers
function Get-FirmwareType {
    try {
        $info = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
        return "$($info.BiosFirmwareType)"   # "Uefi" or "Bios"
    } catch {
        try {
            # Fallback: presence of EFI variables implies UEFI
            $null = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
            return 'Uefi'
        } catch { return 'Unknown' }
    }
}

function Test-SecureBootEnabled {
    try { return [bool](Confirm-SecureBootUEFI) } catch { return $false }
}

function Test-InSetupMode {
    try {
        $sm = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
        # SetupMode is a 1-byte UEFI variable: 1 = in setup mode, 0 = user mode
        return ([int]$sm.Bytes[0] -eq 1)
    } catch {
        return $false
    }
}

function Get-DbCertificateMarkers {
    $markers = [ordered]@{
        MsProductionCa2011 = $false
        UefiCa2023         = $false
    }
    try {
        $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
        $dbText = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $markers.MsProductionCa2011 = ($dbText -match 'Microsoft Windows Production PCA 2011')
        $markers.UefiCa2023         = ($dbText -match 'Windows UEFI CA 2023')
    } catch { }
    return $markers
}

function Get-TpmState {
    try {
        $t = Get-Tpm -ErrorAction Stop
        [pscustomobject]@{
            Present = [bool]$t.TpmPresent
            Ready   = [bool]$t.TpmReady
            Enabled = [bool]$t.TpmEnabled
        }
    } catch {
        [pscustomobject]@{ Present=$false; Ready=$false; Enabled=$false }
    }
}
#endregion

#region Main
try {
    $firmware        = Get-FirmwareType
    $sbEnabled       = Test-SecureBootEnabled
    $setupMode       = Test-InSetupMode
    $dbMarkers       = Get-DbCertificateMarkers
    $tpm             = Get-TpmState

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($RequireUefiFirmware -and $firmware -ne 'Uefi') {
        $reasons.Add("Firmware type is $firmware (required: Uefi).")
    }
    if ($RequireSecureBootOn -and -not $sbEnabled) {
        $reasons.Add("Secure Boot is not enabled in firmware.")
    }
    if ($RequireNotInSetupMode -and $setupMode) {
        $reasons.Add("Platform is in Setup Mode (UEFI keys not enrolled).")
    }
    if ($RequireMsProductionCa -and -not $dbMarkers.MsProductionCa2011) {
        $reasons.Add("Microsoft Windows Production PCA 2011 not present in Secure Boot DB.")
    }
    if ($RequireUefiCa2023 -and -not $dbMarkers.UefiCa2023) {
        $reasons.Add("Windows UEFI CA 2023 certificate not present in Secure Boot DB.")
    }
    if ($RequireTpmReady -and -not $tpm.Ready) {
        $reasons.Add("TPM is not ready (Present=$($tpm.Present), Enabled=$($tpm.Enabled)).")
    }

    $diag = [ordered]@{
        FirmwareType         = $firmware
        SecureBootEnabled    = [bool]$sbEnabled
        InSetupMode          = [bool]$setupMode
        DbHasMsProductionCa  = [bool]$dbMarkers.MsProductionCa2011
        DbHasUefiCa2023      = [bool]$dbMarkers.UefiCa2023
        Tpm                  = $tpm
        NonComplianceReasons = $reasons.ToArray()
        EvaluatedAt          = (Get-Date).ToString('o')
        Requirements         = [ordered]@{
            RequireUefiFirmware   = $RequireUefiFirmware
            RequireSecureBootOn   = $RequireSecureBootOn
            RequireNotInSetupMode = $RequireNotInSetupMode
            RequireMsProductionCa = $RequireMsProductionCa
            RequireUefiCa2023     = $RequireUefiCa2023
            RequireTpmReady       = $RequireTpmReady
        }
    }

    if ($reasons.Count -eq 0) {
        Write-Output "Secure Boot compliant (Firmware=$firmware, SecureBoot=$sbEnabled, SetupMode=$setupMode, MsProductionCa=$($dbMarkers.MsProductionCa2011), TpmReady=$($tpm.Ready))."
        Write-Output "SECUREBOOT_DIAG=$($diag | ConvertTo-Json -Compress -Depth 6)"
        exit 0
    } else {
        Write-Output "Secure Boot NON-COMPLIANT. Reasons:"
        foreach ($r in $reasons) { Write-Output " - $r" }
        Write-Output "SECUREBOOT_DIAG=$($diag | ConvertTo-Json -Compress -Depth 6)"
        exit 1
    }
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    Write-Output "SECUREBOOT_DIAG=$(@{Error=$_.Exception.Message;EvaluatedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress)"
    exit 0
}
#endregion
