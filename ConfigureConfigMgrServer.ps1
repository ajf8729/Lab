[CmdletBinding()]
Param(
)

# Configure disks
Get-Disk | Where-Object {$_.OperationalStatus -eq 'Offline'} | Set-Disk -IsOffline $false
Get-Disk | Where-Object {$_.IsReadOnly -eq $true} | Initialize-Disk -PartitionStyle GPT
New-Volume -DiskNumber 1 -FileSystem NTFS -DriveLetter 'E' -FriendlyName 'SQL'
New-Volume -DiskNumber 2 -FileSystem NTFS -DriveLetter 'F' -FriendlyName 'CM'
New-Item -Path 'F:\' -Name 'SOURCE' -ItemType Directory
New-Item -Path 'F:\' -Name 'WSUS' -ItemType Directory
New-Item -Path 'F:\SOURCE\' -Name 'Downloads' -ItemType Directory

# Install RSAT tools
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-AD-AdminCenter, RSAT-ADDS-Tools, GPMC

# Install gMSA for SQL
Install-ADServiceAccount -Identity 'svc_CM_SQL'
Restart-Computer

# Create NO_SMS_ON_DRIVE.SMS files
New-Item -Path 'C:\' -Name "NO_SMS_ON_DRIVE.SMS" -ItemType File
New-Item -Path 'E:\' -Name "NO_SMS_ON_DRIVE.SMS" -ItemType File
