# Isolated Hyper-V lab for labelled traffic collection (see docs/lab-collection-protocol-2026-11.md)
#
# Run from an ELEVATED PowerShell (Run as administrator). The script:
#   1. checks that Hyper-V is available and enabled (it does NOT enable it unless -EnableHyperV is given;
#      enabling needs a reboot, which you must do yourself);
#   2. creates one INTERNAL virtual switch: VMs on it reach each other and the host only; no
#      external adapter is bound, so traffic cannot leave the host;
#   3. creates two Generation 2 VMs (victim, attacker) attached only to that switch;
#   4. prints the verification steps (no default route, no external switch, Pktmon visibility).
#
# Nothing is downloaded. Give it an OS ISO you placed yourself with -IsoPath.
#
# Example:
#   .\setup_hyperv_lab.ps1 -IsoPath "D:\iso\ubuntu-24.04-live-server-amd64.iso" -DryRun
#   .\setup_hyperv_lab.ps1 -IsoPath "D:\iso\ubuntu-24.04-live-server-amd64.iso"

[CmdletBinding()]
param(
    [string]$SwitchName = "IG-Lab",
    [string]$IsoPath,
    [string]$VmRoot = "$env:PUBLIC\Documents\Hyper-V\IG-Lab",
    [int]$MemoryMB = 2048,
    [int]$DiskGB = 20,
    [switch]$EnableHyperV,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Say($text) { Write-Host "[lab] $text" }

if (-not (Test-Admin)) { throw "Run this script from an elevated PowerShell (Run as administrator)." }

# 1. Hyper-V state
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -ne "Enabled") {
    if ($EnableHyperV) {
        Say "Enabling Hyper-V. A reboot is required before the lab can be created."
        if (-not $DryRun) { Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null }
        Say "Reboot the machine, then run this script again without -EnableHyperV."
        return
    }
    throw "Hyper-V is not enabled. Re-run with -EnableHyperV (then reboot), or enable it yourself."
}
Say "Hyper-V enabled."

# 2. Internal switch: no external adapter bound
$existing = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.SwitchType -ne "Internal") { throw "Switch $SwitchName exists and is not Internal. Refusing to use it." }
    Say "Switch $SwitchName already exists (Internal)."
} elseif ($DryRun) {
    Say "DRY RUN: would create Internal switch $SwitchName."
} else {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Say "Created Internal switch $SwitchName."
}

# 3. Two VMs, attached only to the lab switch
if (-not $IsoPath -or -not (Test-Path $IsoPath)) {
    Say "No ISO given (or path missing). VMs were not created. Pass -IsoPath to an OS image you placed yourself."
    return
}
foreach ($name in @("IG-Victim", "IG-Attacker")) {
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
        Say "VM $name already exists; skipped."
        continue
    }
    if ($DryRun) { Say "DRY RUN: would create VM $name on $SwitchName."; continue }
    New-Item -ItemType Directory -Force -Path $VmRoot | Out-Null
    New-VM -Name $name -Generation 2 -MemoryStartupBytes ($MemoryMB * 1MB) -Path $VmRoot `
        -NewVHDPath (Join-Path $VmRoot "$name.vhdx") -NewVHDSizeBytes ($DiskGB * 1GB) `
        -SwitchName $SwitchName | Out-Null
    Set-VMFirmware -VMName $name -EnableSecureBoot Off
    Add-VMDvdDrive -VMName $name -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $name
    Set-VMFirmware -VMName $name -FirstBootDevice $dvd
    Say "Created VM $name."
}

# 4. Verification checklist (printed, not executed)
Say "Verify before any capture:"
Say "  - Get-VMSwitch $SwitchName : SwitchType must be Internal; no NetAdapterInterfaceDescription."
Say "  - In each VM: no default route (ip route) and no internet (ping 8.8.8.8 must fail)."
Say "  - On the host: pktmon list  (the vEthernet ($SwitchName) component must appear)."
Say "  - Before disconnecting VMs from the internet, install hping3 and nmap inside the attacker VM."
