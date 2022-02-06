[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$ReverseZoneNetworkId,
    [Parameter(Mandatory = $false)]
    [string]$AlternativeUpnSuffix,
    [Parameter(Mandatory = $true)]
    [string]$BaseUsername,
    [Parameter(Mandatory = $true)]
    [string]$GivenName,
    [Parameter(Mandatory = $true)]
    [string]$Initial,
    [Parameter(Mandatory = $true)]
    [string]$Surname
)

# Modules
Import-Module -Name ActiveDirectory
Import-Module -Name DnsServer

# Variables
$T0Password = Read-Host -AsSecureString -Prompt 'Enter domain admin account password'
$T1Password = Read-Host -AsSecureString -Prompt 'Enter server admin account password'
$T2Password = Read-Host -AsSecureString -Prompt 'Enter workstation admin account password'
$T3Password = Read-Host -AsSecureString -Prompt 'Enter user account password'

$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$DomainName = (Get-ADDomain).DNSRoot
$DomainNetBIOSName = (Get-ADDomain).NetBIOSName
$RootOUDistinguishedName = "OU=$($DomainNetBIOSName),$($DomainDistinguishedName)"

$CMServerName = 'CM01'

# Create DNS reverse lookup zone
Add-DnsServerPrimaryZone -NetworkID $ReverseZoneNetworkId -ReplicationScope Domain

# Add alternative UPN suffix
if ($AlternativeUpnSuffix) {
    Set-ADForest -Identity ((Get-ADForest).Name) -UPNSuffixes @{add = "$AlternativeUpnSuffix"}
}

# Create root OUs
New-ADOrganizationalUnit -Name $DomainNetBIOSName -Path $DomainDistinguishedName -Description "$DomainNetBIOSName Root OU"
New-ADOrganizationalUnit -Name 'T0' -Path $DomainDistinguishedName -Description 'Tier 0 Objects'

# Create subOUs
$OUs = (
    'Administrators',
    'Autopilot',
    'Workstations',
    'Groups',
    'Kiosks',
    'Servers',
    'ServiceAccounts',
    'Staging',
    'Users'
)

foreach ($OU in $OUs) {
    New-ADOrganizationalUnit -Name $OU -Path $RootOUDistinguishedName -Description "$DomainNetBIOSName $OU"
}

# Create RBAC groups
$RBAC_InfrastructureAdmins = New-ADGroup -Name 'RBAC_InfrastructureAdmins' -GroupCategory Security -GroupScope Universal -Path "OU=Groups,$RootOUDistinguishedName" -PassThru
$RBAC_ServerAdmins = New-ADGroup -Name 'RBAC_ServerAdmins' -GroupCategory Security -GroupScope Universal -Path "OU=Groups,$RootOUDistinguishedName" -PassThru
$RBAC_WorkstationAdmins = New-ADGroup -Name 'RBAC_WorkstationAdmins' -GroupCategory Security -GroupScope Universal -Path "OU=Groups,$RootOUDistinguishedName" -PassThru

# Create local admin groups
New-ADGroup -Name 'LocalAdmin_Servers' -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,$RootOUDistinguishedName"
New-ADGroup -Name 'LocalAdmin_Workstations' -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,$RootOUDistinguishedName"

# Create root OU admin group
$RootOUAdminGroup = New-ADGroup -Name "OUAdmin_$($DomainNetBIOSName)" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,$RootOUDistinguishedName" -PassThru

# Create subOU admin groups
foreach ($OU in $OUs) {
    New-ADGroup -Name "OUAdmin_$($DomainNetBIOSName)_$($OU)" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,$RootOUDistinguishedName"
}

# Delegate root OU permissions
$OU = "AD:\OU=$($DomainNetBIOSName),$($DomainDistinguishedName)"
$SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $RootOUAdminGroup.SID
$ACL = Get-Acl -Path $OU
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', 'Allow', 1
$ACL.AddAccessRule($ACE)
Set-Acl -Path $OU -AclObject $ACL

# Delegate subOU permissions
foreach ($OU in $OUs) {
    $subOU = "AD:\OU=$($OU),$($RootOUDistinguishedName)"
    $Group = Get-ADGroup -Identity "OUAdmin_$($DomainNetBIOSName)_$($OU)"
    $SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $Group.SID
    $ACL = Get-Acl -Path $subOU
    $ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', 'Allow', 1
    $ACL.AddAccessRule($ACE)
    Set-Acl -Path $subOU -AclObject $ACL
}

# Grant OU admin access
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)" -Members $RBAC_InfrastructureAdmins
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)_Autopilot" -Members $RBAC_WorkstationAdmins
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)_Kiosks" -Members $RBAC_WorkstationAdmins
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)_Workstations" -Members $RBAC_WorkstationAdmins
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)_Servers" -Members $RBAC_ServerAdmins
Add-ADGroupMember -Identity "OUAdmin_$($DomainNetBIOSName)_Staging" -Members $RBAC_WorkstationAdmins

# Grant local admin access
Add-ADGroupMember -Identity 'LocalAdmin_Servers' -Members $RBAC_InfrastructureAdmins
Add-ADGroupMember -Identity 'LocalAdmin_Servers' -Members $RBAC_ServerAdmins
Add-ADGroupMember -Identity 'LocalAdmin_Workstations' -Members $RBAC_WorkstationAdmins

# Create user accounts
$T0 = New-ADUser -Name "$($BaseUsername)-da" -SamAccountName "$($BaseUsername)-da" -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname (DA)" -Path "OU=T0,$DomainDistinguishedName" -UserPrincipalName "$($BaseUsername)-da@$($DomainName)" -AccountPassword $T0Password -PasswordNeverExpires $true -Enabled $true -PassThru
$T1 = New-ADUser -Name "$($BaseUsername)-sa" -SamAccountName "$($BaseUsername)-sa" -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname (SA)" -Path "OU=Administrators,$RootOUDistinguishedName" -UserPrincipalName "$($BaseUsername)-sa@$($DomainName)" -AccountPassword $T1Password -PasswordNeverExpires $true -Enabled $true -PassThru
if ($AlternativeUpnSuffix) {
    $T2 = New-ADUser -Name "$($BaseUsername)-wa" -SamAccountName "$($BaseUsername)-wa" -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname (WA)" -Path "OU=Users,$RootOUDistinguishedName" -UserPrincipalName "$($BaseUsername)-wa@$($AlternativeUpnSuffix)" -AccountPassword $T2Password -PasswordNeverExpires $true -Enabled $true -PassThru
    New-ADUser -Name $BaseUsername -SamAccountName $BaseUsername -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname" -Path "OU=Users,$RootOUDistinguishedName" -UserPrincipalName "$($BaseUsername)@$($AlternativeUpnSuffix)" -AccountPassword $T3Password -PasswordNeverExpires $true -Enabled $true
}
else {
    $T2 = New-ADUser -Name "$($BaseUsername)-wa" -SamAccountName "$($BaseUsername)-wa" -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname (WA)" -Path "OU=Users,$RootOUDistinguishedName" -UserPrincipalName "$($BaseUsername)-wa@$($DomainName)" -AccountPassword $T2Password -PasswordNeverExpires $true -Enabled $true -PassThru
    New-ADUser -Name $BaseUsername -SamAccountName $BaseUsername -GivenName $GivenName -Initials $Initial -Surname $Surname -DisplayName "$GivenName $Initial $Surname" -Path "OU=Users,$RootOUDistinguishedName" -UserPrincipalName "$($BaseUsername)@$($DomainName)" -AccountPassword $T3Password -PasswordNeverExpires $true -Enabled $true
}

# Add users to necessary groups
Add-ADGroupMember -Identity 'Domain Admins' -Members $T0
Add-ADGroupMember -Identity 'Enterprise Admins' -Members $T0
Add-ADGroupMember -Identity 'Schema Admins' -Members $T0
Add-ADGroupMember -Identity 'RBAC_InfrastructureAdmins' -Members $T1
Add-ADGroupMember -Identity 'RBAC_WorkstationAdmins' -Members $T2

# Create KDS root key
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours((-10)))

# Rename default AD site
Get-ADObject -SearchBase ((Get-ADRootDSE).ConfigurationNamingContext) -Filter "objectClass -eq 'site' -and name -eq 'Default-First-Site-Name'" | Rename-ADObject -NewName $DomainNetBIOSName

# Create AD subnet
New-ADReplicationSubnet -Name $ReverseZoneNetworkId -Site $DomainNetBIOSName

# Enable AD recycling bin
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DomainName -Confirm:$false

# Redirect default Computers and Users containers
redircmp.exe "OU=Staging,$RootOUDistinguishedName"
redirusr.exe "OU=Users,$RootOUDistinguishedName"

#Create ConfigMgr objects
New-ADOrganizationalUnit -Name 'CM' -Path "OU=Servers,$RootOUDistinguishedName" -Description 'ConfigMgr'

$CMComputer = New-ADComputer -Name $CMServerName -Path "OU=CM,OU=Servers,$RootOUDistinguishedName" -PassThru

$CM_Servers = New-ADGroup -Name 'CM_Servers' -GroupCategory Security -GroupScope Universal -Path "OU=CM,OU=Servers,$RootOUDistinguishedName" -PassThru
$CM_Admins = New-ADGroup -Name 'CM_Admins' -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,$RootOUDistinguishedName" -PassThru

New-ADGroup -Name 'CM_SQL_Admins' -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,$RootOUDistinguishedName"

Add-ADGroupMember -Identity 'CM_Servers' -Members $CMComputer
Add-ADGroupMember -Identity 'CM_Admins' -Members $CM_Servers
Add-ADGroupMember -Identity 'CM_Admins' -Members $RBAC_InfrastructureAdmins
Add-ADGroupMember -Identity 'CM_SQL_Admins' -Members $CM_Admins

New-ADServiceAccount -Name 'svc_CM_SQL' -SamAccountName 'svc_CM_SQL' -DNSHostName "$($CMServerName).$($DomainName)" -KerberosEncryptionType AES128, AES256 -Path "OU=CM,OU=Servers,$RootOUDistinguishedName" -PrincipalsAllowedToRetrieveManagedPassword (Get-ADGroup -Identity 'CM_Servers')

New-ADObject -Name 'System Management' -Type Container -Path "CN=System,$($DomainDistinguishedName)"

$CN = "AD:\CN=System Management,CN=System,$($DomainDistinguishedName)"
$SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $CM_Admins.SID
$ACL = Get-Acl -Path $CN
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', 'Allow', 1
$ACL.AddAccessRule($ACE)
Set-Acl -Path $CN -AclObject $ACL

# Create central store
New-Item -Path 'C:\Windows\SYSVOL\domain\Policies' -Name PolicyDefinitions -ItemType Directory
Copy-Item -Path 'C:\Windows\PolicyDefinitions\*' -Destination 'C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions\' -Recurse

# Create GPOs
$GPONames = (
    $DomainName,
    'DC - Default Security Policy',
    'All - Default Security Policy',
    'Autopilot - Default Security Policy',
    'Kiosk - Default Security Policy',
    'Server - Default Security Policy',
    'Server - ConfigMgr',
    'Staging - Default Security Policy',
    'User - Default Security Policy',
    'Workstation - Default Security Policy'
)

foreach ($GPOName in $GPONames) {
    New-GPO -Name $GPOName
}

# Set GPO permissions
$GPONames = (
    'All - Default Security Policy',
    'Autopilot - Default Security Policy',
    'Kiosk - Default Security Policy',
    'Server - Default Security Policy',
    'Server - ConfigMgr',
    'Staging - Default Security Policy',
    'User - Default Security Policy',
    'Workstation - Default Security Policy'
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName 'RBAC_InfrastructureAdmins' -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity
}

$GPONames = (
    'Server - Default Security Policy',
    'Server - ConfigMgr'
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName 'RBAC_ServerAdmins' -TargetType Group -PermissionLevel GpoEdit
}

$GPONames = (
    'Autopilot - Default Security Policy',
    'Kiosk - Default Security Policy',
    'Staging - Default Security Policy',
    'Workstation - Default Security Policy'
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName 'RBAC_WorkstationAdmins' -TargetType Group -PermissionLevel GpoEdit
}

# Link GPOs
New-GPLink -Name $DomainName -Target $DomainDistinguishedName -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'DC - Default Security Policy' -Target "OU=Domain Controllers,$DomainDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'All - Default Security Policy' -Target $RootOUDistinguishedName -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Autopilot - Default Security Policy' -Target "OU=Autopilot,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Workstation - Default Security Policy' -Target "OU=Autopilot,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name 'Kiosk - Default Security Policy' -Target "OU=Kiosks,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Workstation - Default Security Policy' -Target "OU=Kiosks,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name 'Server - Default Security Policy' -Target "OU=Servers,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Server - ConfigMgr' -Target "OU=CM,OU=Servers,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Staging - Default Security Policy' -Target "OU=Staging,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Workstation - Default Security Policy' -Target "OU=Staging,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name 'User - Default Security Policy' -Target "OU=Users,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name 'Workstation - Default Security Policy' -Target "OU=Workstations,$RootOUDistinguishedName" -LinkEnabled Yes -Enforced No -Order 1
