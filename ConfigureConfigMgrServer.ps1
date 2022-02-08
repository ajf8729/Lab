[CmdletBinding()]
Param(
)

# Configure disks
Get-Disk | Where-Object {$_.OperationalStatus -eq 'Offline'} | Set-Disk -IsOffline $false
Get-Disk | Where-Object {$_.IsReadOnly -eq $true} | Initialize-Disk -PartitionStyle GPT
New-Volume -DiskNumber 1 -FileSystem NTFS -DriveLetter 'E' -FriendlyName 'SQL' | Out-Null
New-Volume -DiskNumber 2 -FileSystem NTFS -DriveLetter 'F' -FriendlyName 'CM' | Out-Null
New-Item -Path 'F:\' -Name 'SOURCE' -ItemType Directory | Out-Null

# Install RSAT tools
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-AD-AdminCenter, RSAT-ADDS-Tools, GPMC

# Install gMSA for SQL
Install-ADServiceAccount -Identity 'svc_CM_SQL'
Restart-Computer
