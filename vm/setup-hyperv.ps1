#Requires -RunAsAdministrator
# iStoreOS Hyper-V VM setup script
# Run in elevated PowerShell: powershell -ExecutionPolicy Bypass -File .\vm\setup-hyperv.ps1

$ErrorActionPreference = "Stop"

$vmName   = "iStoreOS-Dev"
$vmDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhdSrc   = Join-Path $vmDir "istoreos.vhd"
$vhdxPath = Join-Path $vmDir "istoreos.vhdx"

Write-Host "[1/6] Check Hyper-V module"
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Host "ERROR: Hyper-V PowerShell module not found."
    Write-Host "  Enable it: Settings -> Apps -> Optional Features -> Hyper-V"
    exit 1
}
Import-Module Hyper-V

Write-Host "[2/6] Convert VHD -> VHDX"
if (Test-Path $vhdxPath) {
    Write-Host "  VHDX already exists, skip conversion"
} else {
    Convert-VHD -Path $vhdSrc -DestinationPath $vhdxPath -VHDType Dynamic
}
Resize-VHD -Path $vhdxPath -SizeBytes 4GB
Write-Host "  VHDX ready: $vhdxPath"

Write-Host "[3/6] Create virtual switches"
$wanSwitch = "macflow-WAN"
$lanSwitch = "macflow-LAN"

if (-not (Get-VMSwitch -Name $wanSwitch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $wanSwitch -SwitchType Internal
    Write-Host "  Created internal switch: $wanSwitch"
    $wanAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*$wanSwitch*" }
    if ($wanAdapter) {
        New-NetIPAddress -InterfaceIndex $wanAdapter.ifIndex -IPAddress 10.0.1.1 -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    }
} else {
    Write-Host "  Switch $wanSwitch already exists"
}

if (-not (Get-VMSwitch -Name $lanSwitch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $lanSwitch -SwitchType Internal
    Write-Host "  Created internal switch: $lanSwitch"
    $lanAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*$lanSwitch*" }
    if ($lanAdapter) {
        New-NetIPAddress -InterfaceIndex $lanAdapter.ifIndex -IPAddress 192.168.100.1 -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    }
} else {
    Write-Host "  Switch $lanSwitch already exists"
}

Write-Host "[4/6] Create VM: $vmName"
if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    Write-Host "  VM already exists, removing old one"
    Stop-VM -Name $vmName -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $vmName -Force
}

New-VM -Name $vmName `
    -MemoryStartupBytes 1GB `
    -Generation 2 `
    -VHDPath $vhdxPath `
    -Path $vmDir

Set-VMProcessor -VMName $vmName -Count 2
Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false

Write-Host "[5/6] Configure network adapters"
$existingAdapters = Get-VMNetworkAdapter -VMName $vmName
foreach ($a in $existingAdapters) {
    Remove-VMNetworkAdapter -VMName $vmName -Name $a.Name
}

Add-VMNetworkAdapter -VMName $vmName -Name "WAN" -SwitchName $wanSwitch
Add-VMNetworkAdapter -VMName $vmName -Name "LAN" -SwitchName $lanSwitch

Set-VMFirmware -VMName $vmName -EnableSecureBoot Off

Write-Host "[6/6] Start VM"
Start-VM -Name $vmName

Write-Host ""
Write-Host "=========================================="
Write-Host "  iStoreOS VM is starting!"
Write-Host "  VM Name:    $vmName"
Write-Host "  WAN Switch: $wanSwitch (host: 10.0.1.1/24)"
Write-Host "  LAN Switch: $lanSwitch (host: 192.168.100.1/24)"
Write-Host ""
Write-Host "  After boot, iStoreOS default LAN IP:"
Write-Host "    http://192.168.100.1  (from VM LAN port)"
Write-Host "    or connect via: vmconnect localhost $vmName"
Write-Host ""
Write-Host "  Default login: root (no password)"
Write-Host "=========================================="
