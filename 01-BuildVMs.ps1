# Domain controller

New-VM -Name "LABDC01A" -MemoryStartupBytes 1073741824 -SwitchName External -NewVHDPath "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABDC01A.vhdx" -NewVHDSizeBytes 107374182400 -Path "C:\ProgramData\Microsoft\Windows\Hyper-V\" -Version 10.0 -Generation 2 | Out-Null
Set-VM -Name "LABDC01A" -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMFirmware -VMName "LABDC01A" -EnableSecureBoot Off
Add-VMDvdDrive -VMName "LABDC01A"
Set-VMDvdDrive -VMName "LABDC01A" -Path "C:\AJF8729\ISO\20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
Set-VMFirmware -VMName "LABDC01A" -BootOrder (Get-VMDvdDrive -VMName "LABDC01A"),(Get-VMHardDiskDrive -VMName "LABDC01A")

# ConfigMgr site server

New-VM -Name "LABCM01" -MemoryStartupBytes 1073741824 -SwitchName External -NewVHDPath "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABCM01.vhdx" -NewVHDSizeBytes 107374182400 -Path "C:\ProgramData\Microsoft\Windows\Hyper-V\" -Version 10.0 -Generation 2 | Out-Null
Set-VM -Name "LABCM01" -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMFirmware -VMName "LABCM01" -EnableSecureBoot Off
Add-VMDvdDrive -VMName "LABCM01"
Set-VMDvdDrive -VMName "LABCM01" -Path "C:\AJF8729\ISO\20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
Set-VMFirmware -VMName "LABCM01" -BootOrder (Get-VMDvdDrive -VMName "LABCM01"),(Get-VMHardDiskDrive -VMName "LABCM01")
Add-VMScsiController -VMName "LABCM01"
New-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABCM01-2.vhdx" -SizeBytes 107374182400 -Dynamic | Out-Null
New-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABCM01-3.vhdx" -SizeBytes 107374182400 -Dynamic | Out-Null
Add-VMHardDiskDrive -VMName "LABCM01" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation 0
Add-VMHardDiskDrive -VMName "LABCM01" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation 1
Set-VMHardDiskDrive -VMName "LABCM01" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation 0 -Path 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABCM01-2.vhdx'
Set-VMHardDiskDrive -VMName "LABCM01" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation 1 -Path 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABCM01-3.vhdx'
