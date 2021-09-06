[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$VMName
)

New-VM -Name $VMName -MemoryStartupBytes 1073741824 -SwitchName External -NewVHDPath "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\$VMNAME.vhdx" -NewVHDSizeBytes 107374182400 -Path "C:\ProgramData\Microsoft\Windows\Hyper-V\" -Version 10.0 -Generation 2 | Out-Null
Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Add-VMDvdDrive -VMName $VMName
Set-VMDvdDrive -VMName $VMName -Path "C:\AJF8729\ISO\19043.928.210409-1212.21h1_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
Set-VMFirmware -VMName $VMName -BootOrder (Get-VMDvdDrive -VMName $VMName),(Get-VMHardDiskDrive -VMName $VMName)
