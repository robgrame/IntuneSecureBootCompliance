<#
.SYNOPSIS
    Intune Custom Compliance - Discovery script for Secure Boot
.DESCRIPTION
    Returns a single JSON object (no other output) describing the Secure
    Boot state of the device. Fields are flat to match simple rules in
    SecureBootComplianceRules.json.

    Must be code-signed; the signing cert (or its CA) must be a Trusted
    Publisher / Trusted Root on target devices.

    Output schema:
        FirmwareType         : string  (Uefi | Bios | Unknown)
        SecureBootEnabled    : boolean
        InSetupMode          : boolean
        DbHasMsProductionCa  : boolean
        DbHasUefiCa2023      : boolean
        TpmPresent           : boolean
        TpmReady             : boolean
        TpmEnabled           : boolean
        NonComplianceReasons : string  (' | ' separated)
#>

function Get-FirmwareType {
    try {
        return "$((Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType)"
    } catch {
        try { $null = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop; return 'Uefi' }
        catch { return 'Unknown' }
    }
}

# Suppress non-stdout streams; Custom Compliance discovery must emit ONE JSON line only
$ErrorActionPreference   = 'SilentlyContinue'
$WarningPreference       = 'SilentlyContinue'
$VerbosePreference       = 'SilentlyContinue'
$InformationPreference   = 'SilentlyContinue'
$ProgressPreference      = 'SilentlyContinue'

try {
    $firmware  = Get-FirmwareType
    $sbEnabled = $false
    try { $sbEnabled = [bool](Confirm-SecureBootUEFI) } catch { }

    $setupMode = $false
    try {
        $sm = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
        $setupMode = ([int]$sm.Bytes[0] -eq 1)
    } catch { }

    $hasMsCa   = $false
    $hasCa2023 = $false
    try {
        $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
        $dbText = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $hasMsCa   = ($dbText -match 'Microsoft Windows Production PCA 2011')
        $hasCa2023 = ($dbText -match 'Windows UEFI CA 2023')
    } catch { }

    $tpmPresent = $false; $tpmReady = $false; $tpmEnabled = $false
    try {
        $t = Get-Tpm -ErrorAction Stop
        $tpmPresent = [bool]$t.TpmPresent
        $tpmReady   = [bool]$t.TpmReady
        $tpmEnabled = [bool]$t.TpmEnabled
    } catch { }

    $reasons = New-Object System.Collections.Generic.List[string]
    if ($firmware -ne 'Uefi')     { $reasons.Add("Firmware is $firmware") }
    if (-not $sbEnabled)          { $reasons.Add("Secure Boot disabled") }
    if ($setupMode)               { $reasons.Add("Platform in Setup Mode") }
    if (-not $hasMsCa)            { $reasons.Add("Missing Microsoft Production PCA 2011 in DB") }
    if (-not $tpmReady)           { $reasons.Add("TPM not ready") }

    $result = [ordered]@{
        FirmwareType         = "$firmware"
        SecureBootEnabled    = [bool]$sbEnabled
        InSetupMode          = [bool]$setupMode
        DbHasMsProductionCa  = [bool]$hasMsCa
        DbHasUefiCa2023      = [bool]$hasCa2023
        TpmPresent           = [bool]$tpmPresent
        TpmReady             = [bool]$tpmReady
        TpmEnabled           = [bool]$tpmEnabled
        NonComplianceReasons = ($reasons -join ' | ')
    }

    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-Output (@{
        FirmwareType         = "Unknown"
        SecureBootEnabled    = $false
        InSetupMode          = $false
        DbHasMsProductionCa  = $false
        DbHasUefiCa2023      = $false
        TpmPresent           = $false
        TpmReady             = $false
        TpmEnabled           = $false
        NonComplianceReasons = "Discovery error: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress)
    exit 0
}
