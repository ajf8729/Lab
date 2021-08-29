New-VM -Name "LABDC01A" -MemoryStartupBytes 1073741824 -SwitchName External -NewVHDPath "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\LABDC01A.vhdx" -NewVHDSizeBytes 107374182400 -Path "C:\ProgramData\Microsoft\Windows\Hyper-V\" -Version 10.0 -Generation 2 | Out-Null
Set-VM -Name "LABDC01A" -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMFirmware -VMName "LABDC01A" -EnableSecureBoot Off
Add-VMDvdDrive -VMName "LABDC01A"
Set-VMDvdDrive -VMName "LABDC01A" -Path "C:\AJF8729\ISO\20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
Set-VMFirmware -VMName "LABDC01A" -BootOrder (Get-VMDvdDrive -VMName "LABDC01A"),(Get-VMHardDiskDrive -VMName "LABDC01A")
