[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$LabName,
    [Parameter(Mandatory = $true)]
    [string]$VMHostname,
    [Parameter(Mandatory = $true)]
    [int]$MemoryStartupMB,
    [Parameter(Mandatory = $true)]
    [int]$MemoryMaximumMB,
    [Parameter(Mandatory = $true)]
    [int]$ProcessorCount,
    [Parameter(Mandatory = $true)]
    [string]$VirtualSwitchName,
    [Parameter(Mandatory = $true)]
    [int]$DiskCount,
    [Parameter(Mandatory = $true)]
    [string]$VHDPath,
    [Parameter(Mandatory = $true)]
    [int]$VHDSizeGB,
    [Parameter(Mandatory = $true)]
    [string]$ISOPath
)

$VMName = "$LabName-$VMHostname"

# Create VM
$Parameters = @{
    Name               = $VMName
    MemoryStartupBytes = $MemoryStartupMB * 1048576
    SwitchName         = $VirtualSwitchName
    NewVHDPath         = "$VHDPath\$VMName-01.vhdx"
    NewVHDSizeBytes    = $VHDSizeGB * 1073741824
    Generation         = 2
}
New-VM @Parameters

# Configure VM
Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false
Set-VM -Name $VMName -MemoryMaximumBytes ($MemoryMaximumMB * 1048576)
Set-VM -VMName $VMName -ProcessorCount $ProcessorCount
Add-VMDvdDrive -VMName $VMName
Set-VMDvdDrive -VMName $VMName -Path $ISOPath
Set-VMFirmware -VMName $VMName -BootOrder (Get-VMDvdDrive -VMName $VMName), (Get-VMHardDiskDrive -VMName $VMName)

# Enable TPM
$HgsGuardian = Get-HgsGuardian -Name UntrustedGuardian
$HgsKeyProtector = New-HgsKeyProtector -Owner $HgsGuardian -AllowUntrustedRoot
Set-VMKeyProtector -VMName $VMName -KeyProtector $HgsKeyProtector.RawData
Enable-VMTPM -VMName $VMName
Set-VMSecurity -VMName $VMName -EncryptStateAndVmMigrationTraffic $true

# Add additional disks if specified
if ($DiskCount -gt 1) {
    Add-VMScsiController -VMName $VMName
    for ($i = 2; $i -le $DiskCount; $i++) {
        $DiskNumber = $i.ToString('00')
        New-VHD -Path "$VHDPath\$VMName-$DiskNumber.vhdx" -SizeBytes ($VHDSizeGB * 1073741824)
        Add-VMHardDiskDrive -VMName $VMName -ControllerType SCSI -ControllerNumber 1 -ControllerLocation ($i - 2)
        Set-VMHardDiskDrive -VMName $VMName -ControllerType SCSI -ControllerNumber 1 -ControllerLocation ($i - 2) -Path "$VHDPath\$VMName-$DiskNumber.vhdx"
    }
}
