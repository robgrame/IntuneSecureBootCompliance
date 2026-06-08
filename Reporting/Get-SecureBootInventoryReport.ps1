<#
.SYNOPSIS
    Generates a detailed Secure Boot INVENTORY report from Intune Remediations.
.DESCRIPTION
    Queries Microsoft Graph for the device run states of the
    Detect-SecureBootState.ps1 inventory script and extracts the
    SECUREBOOT_STATE={json} payload, producing CSV (+ optional HTML)
    with one row per device.

    Works for both the inventory script (exit 0 -> detectionScriptOutput)
    and the compliance script (exit 1 -> preRemediationDetectionScriptOutput).

    Permissions: DeviceManagementManagedDevices.Read.All,
                 DeviceManagementConfiguration.Read.All
.EXAMPLE
    Connect-MgGraph -Scopes DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All
    .\Get-SecureBootInventoryReport.ps1 -ScriptId <GUID> -OutputCsv .\sb-inv.csv -OutputHtml .\sb-inv.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ScriptId,
    [Parameter(Mandatory)] [string] $OutputCsv,
    [string] $OutputHtml
)

if (-not (Get-MgContext)) {
    throw "Run Connect-MgGraph first with DeviceManagementManagedDevices.Read.All and DeviceManagementConfiguration.Read.All scopes."
}

$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$ScriptId/deviceRunStates?`$expand=managedDevice&`$top=500"

$rows = New-Object System.Collections.Generic.List[object]
do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    foreach ($run in $resp.value) {
        $output = "$($run.detectionScriptOutput)$([Environment]::NewLine)$($run.preRemediationDetectionScriptOutput)"
        $state  = $null
        $match  = [regex]::Match($output, '(?:SECUREBOOT_STATE|SECUREBOOT_DIAG)=(\{.*\})')
        if ($match.Success) {
            try { $state = $match.Groups[1].Value | ConvertFrom-Json } catch { }
        }
        $rows.Add([pscustomobject]@{
            DeviceName          = $run.managedDevice.deviceName
            UserPrincipalName   = $run.managedDevice.userPrincipalName
            OSVersion           = $run.managedDevice.osVersion
            LastUpdate          = $run.lastStateUpdateDateTime
            Manufacturer        = $state.Manufacturer
            Model               = $state.Model
            BiosVersion         = $state.BiosVersion
            FirmwareType        = $state.FirmwareType
            SecureBootEnabled   = $state.SecureBootEnabled
            InSetupMode         = $state.InSetupMode
            DbHasMsProductionCa = $state.DbCertificates.MsProductionCa2011
            DbHasUefiCa2023     = $state.DbCertificates.UefiCa2023
            TpmPresent          = $state.Tpm.Present
            TpmReady            = $state.Tpm.Ready
            TpmManufacturer     = $state.Tpm.ManufacturerIdTxt
            RawOutput           = $output
        })
    }
    $uri = $resp.'@odata.nextLink'
} while ($uri)

$rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $($rows.Count) rows to $OutputCsv"

if ($OutputHtml) {
    $legacyBios = $rows | Where-Object { $_.FirmwareType -ne 'Uefi' }
    $sbOff      = $rows | Where-Object { -not $_.SecureBootEnabled }
    $byModel    = $rows | Group-Object Manufacturer,Model |
                  Sort-Object Count -Descending |
                  Select-Object @{n='Manufacturer/Model';e={$_.Name}}, Count

    $style = @'
<style>
body{font-family:Segoe UI,Arial;margin:24px;color:#222}
h1{font-size:20px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}
th{background:#f3f3f3}
</style>
'@
    $summary  = "<h1>Secure Boot Inventory Report</h1>" +
                "<p>Generated $(Get-Date -Format o). Total devices: $($rows.Count). Legacy BIOS: $($legacyBios.Count). Secure Boot OFF: $($sbOff.Count).</p>"
    $models   = $byModel | ConvertTo-Html -Fragment -PreContent '<h2>Devices by hardware</h2>'
    $detail   = $rows | Select-Object DeviceName,UserPrincipalName,Manufacturer,Model,BiosVersion,FirmwareType,SecureBootEnabled,InSetupMode,DbHasMsProductionCa,DbHasUefiCa2023,TpmReady,LastUpdate |
                ConvertTo-Html -Fragment -PreContent '<h2>Per-device detail</h2>'
    "<html><head>$style</head><body>$summary$models$detail</body></html>" | Set-Content -Path $OutputHtml -Encoding UTF8
    Write-Host "Wrote HTML report to $OutputHtml"
}
