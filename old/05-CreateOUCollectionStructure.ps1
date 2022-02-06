Import-Module -Name ActiveDirectory
Import-Module -FullyQualifiedName "$env:SMS_ADMIN_UI_PATH\..\..\bin\ConfigurationManager.psd1"

Set-Location -Path "LAB:"

if (-not (Test-Path -Path "LAB:\DeviceCollection\lab.ajf8729.com")) {
    New-Item -Path "LAB:\DeviceCollection\" -Name "lab.ajf8729.com" -ItemType Folder
}

if (-not (Test-Path -Path "LAB:\UserCollection\lab.ajf8729.com")) {
    New-Item -Path "LAB:\UserCollection\" -Name "lab.ajf8729.com" -ItemType Folder
}

$DomainDN = Get-ADDomain -Identity "lab.ajf8729.com" | Select-Object -ExpandProperty DistinguishedName

$RefreshSchedule = New-CMSchedule -RecurCount 1 -RecurInterval Days

# Create device collections

$FolderPath = "LAB:\DeviceCollection\lab.ajf8729.com"

$OUNames = (
    "Domain Controllers",
    "LAB",
    "T0"
)

foreach ($OUName in $OUNames) {
    $OU = Get-ADOrganizationalUnit -Identity "OU=$OUName,$DomainDN" -Properties CanonicalName,DistinguishedName,Name,Description | Select-Object -Property CanonicalName,DistinguishedName,Name,Description | Sort-Object -Property CanonicalName
    if (-not (Get-CMCollection -Name $OU.CanonicalName)) {
        $Collection = New-CMCollection -CollectionType Device -LimitingCollectionName "All Systems" -Name $OU.CanonicalName -RefreshSchedule $RefreshSchedule -Comment $OU.DistinguishedName
        Add-CMDeviceCollectionQueryMembershipRule -CollectionName $OU.CanonicalName -QueryExpression "select * from SMS_R_System where SMS_R_System.SystemOUName = '$($OU.CanonicalName)'" -RuleName $OU.CanonicalName
        Move-CMObject -FolderPath $FolderPath -ObjectId $Collection.CollectionID
    }
}

$OUNames = (
    "Autopilot",
    "Servers",
    "Staging",
    "Workstations"
)

foreach ($OUName in $OUNames) {
    $OU = Get-ADOrganizationalUnit -Identity "OU=$OUName,OU=LAB,$DomainDN" -Properties CanonicalName,DistinguishedName,Name,Description | Select-Object -Property CanonicalName,DistinguishedName,Name,Description | Sort-Object -Property CanonicalName
    if (-not (Get-CMCollection -Name $OU.CanonicalName)) {
        $Collection = New-CMCollection -CollectionType Device -LimitingCollectionName "lab.ajf8729.com/LAB" -Name $OU.CanonicalName -RefreshSchedule $RefreshSchedule -Comment $OU.DistinguishedName
        Add-CMDeviceCollectionQueryMembershipRule -CollectionName $OU.CanonicalName -QueryExpression "select * from SMS_R_System where SMS_R_System.SystemOUName = '$($OU.CanonicalName)'" -RuleName $OU.CanonicalName
        Move-CMObject -FolderPath $FolderPath -ObjectId $Collection.CollectionID
    }
}

# Create user collections

$FolderPath = "LAB:\UserCollection\lab.ajf8729.com"

$OUNames = (
    "T0"
)

foreach ($OUName in $OUNames) {
    $OU = Get-ADOrganizationalUnit -Identity "OU=$OUName,$DomainDN" -Properties CanonicalName,DistinguishedName,Name,Description | Select-Object -Property CanonicalName,DistinguishedName,Name,Description | Sort-Object -Property CanonicalName
    if (-not (Get-CMCollection -Name "$($OU.CanonicalName) (Users)")) {
        $Collection = New-CMCollection -CollectionType User -LimitingCollectionName "All Users" -Name "$($OU.CanonicalName) (Users)" -RefreshSchedule $RefreshSchedule -Comment $OU.DistinguishedName
        Add-CMUserCollectionQueryMembershipRule -CollectionName "$($OU.CanonicalName) (Users)" -QueryExpression "select * from SMS_R_User where SMS_R_User.UserOUName = '$($OU.CanonicalName)'" -RuleName $OU.CanonicalName
        Move-CMObject -FolderPath $FolderPath -ObjectId $Collection.CollectionID
    }
}

$OUNames = (
    "Administrators",
    "Users"
)

foreach ($OUName in $OUNames) {
    $OU = Get-ADOrganizationalUnit -Identity "OU=$OUName,OU=LAB,$DomainDN" -Properties CanonicalName,DistinguishedName,Name,Description | Select-Object -Property CanonicalName,DistinguishedName,Name,Description | Sort-Object -Property CanonicalName
    if (-not (Get-CMCollection -Name "$($OU.CanonicalName) (Users)")) {
        $Collection = New-CMCollection -CollectionType User -LimitingCollectionName "All Users" -Name "$($OU.CanonicalName) (Users)" -RefreshSchedule $RefreshSchedule -Comment $OU.DistinguishedName
        Add-CMUserCollectionQueryMembershipRule -CollectionName "$($OU.CanonicalName) (Users)" -QueryExpression "select * from SMS_R_User where SMS_R_User.UserOUName = '$($OU.CanonicalName)'" -RuleName $OU.CanonicalName
        Move-CMObject -FolderPath $FolderPath -ObjectId $Collection.CollectionID
    }
}
