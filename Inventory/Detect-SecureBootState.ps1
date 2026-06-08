<#
.SYNOPSIS
    Intune Detection Script - Secure Boot INVENTORY (state only, no compliance verdict)
.DESCRIPTION
    Reports the current Secure Boot / firmware / TPM state of the device.
    Designed to be deployed as an Intune Remediation with ONLY the detection
    script (Remediation script left empty). Always exits 0 so every device
    contributes to inventory regardless of state.

    Output:
    - Human-readable summary lines
    - A single machine-parsable line: SECUREBOOT_STATE={...json...}

    Exit code:
        0 = always
#>

function Get-FirmwareType {
    try {
        return "$((Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType)"
    } catch {
        try { $null = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop; return 'Uefi' }
        catch { return 'Unknown' }
    }
}

function Get-DbCertMarkers {
    $r = [ordered]@{ MsProductionCa2011=$false; UefiCa2023=$false; ThirdPartyUefiCa2011=$false }
    try {
        $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
        $t  = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $r.MsProductionCa2011    = ($t -match 'Microsoft Windows Production PCA 2011')
        $r.UefiCa2023            = ($t -match 'Windows UEFI CA 2023')
        $r.ThirdPartyUefiCa2011  = ($t -match 'Microsoft Corporation UEFI CA 2011')
    } catch { }
    return $r
}

function Get-DbxRevocationCount {
    try {
        (Get-SecureBootUEFI -Name dbx -ErrorAction Stop).Bytes.Length
    } catch { -1 }
}

function Get-SetupMode {
    try {
        $sm = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
        [bool]([int]$sm.Bytes[0] -eq 1)
    } catch { $false }
}

function Get-TpmSummary {
    try {
        $t = Get-Tpm -ErrorAction Stop
        [ordered]@{
            Present             = [bool]$t.TpmPresent
            Ready               = [bool]$t.TpmReady
            Enabled             = [bool]$t.TpmEnabled
            Activated           = [bool]$t.TpmActivated
            Owned               = [bool]$t.TpmOwned
            ManufacturerIdTxt   = "$($t.ManufacturerIdTxt)"
            ManufacturerVersion = "$($t.ManufacturerVersion)"
        }
    } catch {
        [ordered]@{ Present=$false; Ready=$false; Enabled=$false; Error="$($_.Exception.Message)" }
    }
}

try {
    $firmware        = Get-FirmwareType
    $sbEnabled       = $false
    try { $sbEnabled = [bool](Confirm-SecureBootUEFI) } catch { }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    $state = [ordered]@{
        DeviceName          = $env:COMPUTERNAME
        Manufacturer        = "$($cs.Manufacturer)"
        Model               = "$($cs.Model)"
        BiosVersion         = "$($bios.SMBIOSBIOSVersion)"
        FirmwareType        = $firmware
        SecureBootEnabled   = [bool]$sbEnabled
        InSetupMode         = (Get-SetupMode)
        DbCertificates      = (Get-DbCertMarkers)
        DbxBytes            = (Get-DbxRevocationCount)
        Tpm                 = (Get-TpmSummary)
        CollectedAt         = (Get-Date).ToString('o')
    }

    Write-Output "Secure Boot inventory for $($env:COMPUTERNAME)"
    Write-Output (" Manufacturer  : {0}" -f $state.Manufacturer)
    Write-Output (" Model         : {0}" -f $state.Model)
    Write-Output (" BIOS version  : {0}" -f $state.BiosVersion)
    Write-Output (" FirmwareType  : {0}" -f $firmware)
    Write-Output (" SecureBoot    : {0}" -f $sbEnabled)
    Write-Output (" SetupMode     : {0}" -f $state.InSetupMode)
    Write-Output (" DB MsProdCA   : {0}" -f $state.DbCertificates.MsProductionCa2011)
    Write-Output (" DB UEFI CA2023: {0}" -f $state.DbCertificates.UefiCa2023)
    Write-Output (" TPM ready     : {0}" -f $state.Tpm.Ready)
    Write-Output "SECUREBOOT_STATE=$($state | ConvertTo-Json -Compress -Depth 6)"
    exit 0
}
catch {
    Write-Output "Inventory error: $($_.Exception.Message)"
    Write-Output "SECUREBOOT_STATE=$(@{Error=$_.Exception.Message;CollectedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress)"
    exit 0
}
