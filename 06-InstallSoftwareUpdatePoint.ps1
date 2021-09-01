Import-Module -FullyQualifiedName "$env:SMS_ADMIN_UI_PATH\..\..\bin\ConfigurationManager.psd1"

Set-Location -Path "LAB:"

Add-CMSoftwareUpdatePoint -SiteSystemServerName "labcm01.lab.ajf8729.com" -ClientConnectionType Intranet -WsusSsl $false -WsusIisPort 8530 -WsusIisSslPort 8531

# Configure WSUS Maintenance options

$WSUS = Get-WmiObject -Namespace "root\sms\site_LAB" -Class "SMS_SCI_Component" | Where-Object -FilterScript {$_.ComponentName -eq "SMS_WSUS_CONFIGURATION_MANAGER"}
$WSUS.Get()
$Props = $WSUS.Props
foreach ($Prop in $Props) {
    # Decline expired updates in WSUS according to supersedence rules
    if ($prop.PropertyName -eq "Call WSUS Cleanup") {$Prop.Value = 1}
    # Add non-clustered indexes to the WSUS database
    if ($prop.PropertyName -eq "Call WSUS Indexing") {$Prop.Value = 1}
    # Remove obsolete updates from the WSUS database
    if ($prop.PropertyName -eq "Call WSUS Delete Obselete Updates") {$Prop.Value = 1}
}
$WSUS.Props = $Props
$WSUS.Put() | Out-Null

# Enable synchronization and set schedule

Set-CMSoftwareUpdatePointComponent -Schedule (New-CMSchedule -RecurCount 1 -RecurInterval Days -Start 2021-08-01T15:00:00-04:00)

# Start full synchronization

Sync-CMSoftwareUpdate -FullSync $true

# Enable third party updates

Set-CMSoftwareUpdatePointComponent -EnableThirdPartyUpdates $true -EnableManualCertManagement $false

#Add classifications and products

Set-CMSoftwareUpdatePointComponent -AddUpdateClassification "Security Updates"
Set-CMSoftwareUpdatePointComponent -AddUpdateClassification Updates
Set-CMSoftwareUpdatePointComponent -AddProduct "Microsoft Server operating system-21H2"
Sync-CMSoftwareUpdate -FullSync $true

# Enable software-update based client installation

Set-CMSoftwareUpdateBasedClientInstallation -EnableWsus $true
