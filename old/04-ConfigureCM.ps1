Import-Module -FullyQualifiedName "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

Set-Location -Path "LAB:"

# Enable all site features

Get-CMSiteFeature -Fast | Where-Object -FilterScript {$_.Status -eq "0"} | Enable-CMSiteFeature -Force -Verbose

# Configure discovery

Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -Enabled $true -EnableActiveDirectorySiteBoundaryCreation $true -PollingSchedule (New-CMSchedule -RecurCount 7 -RecurInterval Days)
Invoke-CMForestDiscovery

Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -Enabled $true -AddGroupDiscoveryScope (New-CMADGroupDiscoveryScope -LdapLocation "LDAP://DC=lab,DC=dev,DC=ajf8729,DC=com" -Name "lab.dev.ajf8729.com" -RecursiveSearch $true) -PollingSchedule (New-CMSchedule -RecurCount 1 -RecurInterval Days) -EnableFilteringExpiredLogon $true -EnableFilteringExpiredPassword $true
Invoke-CMGroupDiscovery

Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -Enabled $true -AddActiveDirectoryContainer "LDAP://DC=lab,DC=dev,DC=ajf8729,DC=com" -EnableIncludeGroup $true -EnableRecursive $true -PollingSchedule (New-CMSchedule -RecurCount 1 -RecurInterval Days) -EnableFilteringExpiredLogon $true -EnableFilteringExpiredPassword $true
Invoke-CMSystemDiscovery

Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -Enabled $true -AddActiveDirectoryContainer "LDAP://DC=lab,DC=dev,DC=ajf8729,DC=com" -EnableIncludeGroup $true -EnableRecursive $true -PollingSchedule (New-CMSchedule -RecurCount 1 -RecurInterval Days)
Invoke-CMUserDiscovery

# Configure boundary & boundary group

New-CMBoundaryGroup -Name "LAB" -DefaultSiteCode "LAB" -AddSiteSystemServerName "labcm01.lab.dev.ajf8729.com" | Out-Null
Add-CMBoundaryToGroup -BoundaryName "lab.dev.ajf8729.com/LAB" -BoundaryGroupName "LAB"

# Configure default boundary group

Invoke-CimMethod -InputObject (Get-CimInstance -Namespace "root\sms\site_LAB" -ClassName SMS_DefaultBoundaryGroup) -MethodName AddSiteSystem -Arguments @{ServerNALPath = [string[]]'["Display=\\LABCM01.lab.dev.ajf8729.com\"]MSWNET:["SMS_SITE=LAB"]\\LABCM01.lab.dev.ajf8729.com\'; Flags=([System.UInt32[]]0)}

# Site properties

Set-CMSite -SiteCode "LAB" -UseEncryption $true

# Hierarchy settings

Set-CMHierarchySetting -EnablePrereleaseFeature -Force
Set-CMHierarchySetting -EnableAutoClientUpgrade $true -AutomaticallyUpgradeDays 1 -Force

# DP Group

New-CMDistributionPointGroup -Name "ALL" | Out-Null
Add-CMDistributionPointToGroup -DistributionPointGroupName "ALL" -DistributionPointName "labcm01.lab.dev.ajf8729.com"
