$Parameters = @{
    LabName           = 'LAB'
    VMHostname        = 'LABDC01A'
    MemoryStartupMB   = 1024
    MemoryMaximumMB   = 2048
    ProcessorCount    = 2
    VirtualSwitchName = 'LAB'
    DiskCount         = 1
    VHDPath           = 'D:\VHD\'
    VHDSizeGB         = 100
    ISOPath           = 'E:\Software\Windows Server 2022\20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'
}

.\New-LabVM.ps1 @Parameters
