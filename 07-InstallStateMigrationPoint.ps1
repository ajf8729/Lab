Import-Module -FullyQualifiedName "$env:SMS_ADMIN_UI_PATH\..\..\bin\ConfigurationManager.psd1"

Set-Location -Path "LAB:"

New-Item -Path "F:\" -Name "SMP" -ItemType Directory | Out-Null
$StorageFolder = New-CMStorageFolder -StorageFolderName "F:\SMP" -MaximumClientNumber 5 -MinimumFreeSpace 1 -SpaceUnit Gigabyte
Add-CMStateMigrationPoint -SiteSystemServerName "labcm01.lab.ajf8729.com" -StorageFolder $StorageFolder -BoundaryGroupName LAB -TimeDeleteAfter 5 -TimeUnit Days -Verbose
