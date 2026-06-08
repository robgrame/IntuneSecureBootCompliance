# Intune Secure Boot Compliance — diagnostica dettagliata

Soluzione custom per Microsoft Intune (Windows 10/11) che espone il
**motivo specifico** per cui un device risulta non conforme rispetto a
Secure Boot, problema che la Compliance Policy built-in di Intune non
dettaglia (valutazione binaria del setting `RequireSecureBoot`).

Stessa architettura **two-tier** della soluzione gemella
[IntuneBitLockerCompliance](https://github.com/robgrame/IntuneBitLockerCompliance):

```
Remediations/
  Detect-SecureBootCompliance.ps1     # Intune Remediations - detection
  Remediate-SecureBootCompliance.ps1  # Intune Remediations - guidance only
CustomCompliance/
  Discover-SecureBoot.ps1             # Discovery script (DEVE essere firmato)
  SecureBootComplianceRules.json      # Regole + messaggi IT/EN per Company Portal
```

## Livello A — Intune Remediations (visibilità immediata)

`Detect-SecureBootCompliance.ps1` raccoglie:

- `FirmwareType` (UEFI vs legacy BIOS, da `Get-ComputerInfo`)
- `SecureBootEnabled` (`Confirm-SecureBootUEFI`)
- `InSetupMode` (UEFI variable `SetupMode`)
- `DbHasMsProductionCa` / `DbHasUefiCa2023` (parsing variabile UEFI `db`)
- Stato TPM (`Get-Tpm`)
- Lista `NonComplianceReasons` human-readable

Output dual-format:

```
SECUREBOOT_DIAG={"FirmwareType":"Uefi","SecureBootEnabled":true,...}
```

visibile nella colonna **Pre-remediation detection output** del report
Remediations di Intune.

### Remediate

A differenza di BitLocker, **non esistono azioni sicure** rimediabili
dall'OS per Secure Boot: abilitazione SB, conversione BIOS→UEFI,
enrollment di PK/KEK/DB richiedono operazioni firmware. Lo script
`Remediate-SecureBootCompliance.ps1` quindi **NON agisce**: logga lo
stato e le azioni manuali richieste, ed esce con `1` per mantenere il
device flaggato.

Per lo scenario specifico del **rollout certificato 2023** (registry
`AvailableUpdates=0x5944`) esistono script dedicati e sicuri, separati
da questa soluzione.

## Livello B — Custom Compliance Settings

`Discover-SecureBoot.ps1` ritorna un JSON flat. `SecureBootComplianceRules.json`
contiene 5 regole con `RemediationStrings` IT/EN che spiegano all'utente
nel Company Portal *cosa* fare quando il device è non conforme.

## Schema diagnostico (Custom Compliance)

| Campo | Tipo | Note |
|------|------|------|
| FirmwareType | String | `Uefi` / `Bios` / `Unknown` |
| SecureBootEnabled | Boolean | |
| InSetupMode | Boolean | UEFI in setup mode = mancano le chiavi platform |
| DbHasMsProductionCa | Boolean | Microsoft Windows Production PCA 2011 |
| DbHasUefiCa2023 | Boolean | Windows UEFI CA 2023 (post-rollout) |
| TpmPresent / TpmReady / TpmEnabled | Boolean | |
| NonComplianceReasons | String | concatenate con ` \| ` |

## Mappa cause → azione

| Reason | Azione |
|--------|--------|
| `Firmware is Bios` | Convertire MBR→GPT con `mbr2gpt.exe`, poi switch UEFI nel firmware |
| `Secure Boot disabled` | Abilitarlo nel menu UEFI; valutare BIOS config profile via Dell Command / HP CMSL / Lenovo BCU per remediation di flotta |
| `Platform in Setup Mode` | Restore Secure Boot default keys dal menu UEFI |
| `Missing Microsoft Production PCA 2011 in DB` | Restore Secure Boot defaults o vendor firmware update |
| `TPM not ready` | Abilitare TPM nel firmware; eventualmente `Initialize-Tpm` |

## Deployment

### Livello A (Remediations)

**Devices → Scripts and remediations → + Create**
- Detection: `Detect-SecureBootCompliance.ps1`
- Remediation: `Remediate-SecureBootCompliance.ps1`
- Run as system = Yes, 64-bit = Yes
- Assign al gruppo target, schedule giornaliero
- Risultati: **Reports → Remediations → device status** → colonna
  *Pre-remediation detection output* → cercare riga `SECUREBOOT_DIAG=`

### Livello B (Custom Compliance)

Lo script va caricato **prima**, in una sezione separata:

1. **Devices → Compliance → Scripts** (tab in alto) → **+ Add → Windows 10 and later**
   - Detection script: `Discover-SecureBoot.ps1` (firmato)
   - `Run this script using the logged on credentials` = **No**
   - `Enforce script signature check` = **Yes**
   - `Run script in 64-bit PowerShell host` = **Yes**
2. **Devices → Compliance → Policies → + Create policy** → Windows 10/11
   - In *Compliance settings* aprire **Custom Compliance**
   - **Select your discovery script** → scegli quello del passo 1
   - **Upload and validate the JSON file** → carica `SecureBootComplianceRules.json`
3. Assign al gruppo, Create.

### Firma del discovery script (obbligatoria)

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature `
  -FilePath .\CustomCompliance\Discover-SecureBoot.ps1 `
  -Certificate $cert `
  -TimestampServer 'http://timestamp.digicert.com' `
  -HashAlgorithm SHA256
```

Il cert firmatario (o la sua CA) deve essere distribuito come
**Trusted Publisher / Trusted Root** sui device target (Intune →
Configuration profiles → Certificates).

## Reporting aggregato

`Reporting\Get-SecureBootComplianceReport.ps1` interroga Microsoft Graph
(`deviceManagement/deviceHealthScripts/{id}/deviceRunStates`), estrae la
riga `SECUREBOOT_DIAG={json}` e produce CSV + (opzionale) HTML con una
riga per device + sommario delle cause più frequenti.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All
.\Reporting\Get-SecureBootComplianceReport.ps1 `
    -ScriptId '<GUID-del-detection-script>' `
    -OutputCsv .\secureboot.csv `
    -OutputHtml .\secureboot.html
```

`ScriptId` reperibile dall'URL del Remediation nel portale Intune o via
`Get-MgBetaDeviceManagementDeviceHealthScript` per displayName.

## Scope

- Windows 10 / Windows 11 client
- Windows Server: fuori scope
- Non automatizza interventi firmware (per definizione di sicurezza)
