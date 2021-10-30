Import-Module -Name ActiveDirectory
Import-Module -Name DnsServer

# Variables

$DAPassword = Read-Host -Prompt "Enter domain admin account password" -AsSecureString
$SAPassword = Read-Host -Prompt "Enter server admin account password" -AsSecureString
$WAPassword = Read-Host -Prompt "Enter workstation admin account password" -AsSecureString
$Password = Read-Host -Prompt "Enter user account password" -AsSecureString

# Create DNS reverse lookup zone

Add-DnsServerPrimaryZone -NetworkID "172.20.1.0/24" -ReplicationScope Domain

# Create root OUs

New-ADOrganizationalUnit -Name "LAB" -Path "DC=lab,DC=ajf8729,DC=com" -Description "LAB Root OU"
New-ADOrganizationalUnit -Name "T0" -Path "DC=lab,DC=ajf8729,DC=com" -Description "Tier 0 Objects"

# Create subOUs

$OUs = (
    "Administrators",
    "Autopilot",
    "Workstations",
    "Groups",
    "Kiosks",
    "Servers",
    "ServiceAccounts",
    "Staging",
    "Users"
)

foreach ($OU in $OUs) {
    New-ADOrganizationalUnit -Name $OU -Path "OU=LAB,DC=lab,DC=ajf8729,DC=com" -Description "LAB $OU"
}

# Create RBAC groups

New-ADGroup -Name "RBAC_InfrastructureAdmins" -GroupCategory Security -GroupScope Universal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "RBAC_ServerAdmins" -GroupCategory Security -GroupScope Universal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "RBAC_WorkstationAdmins" -GroupCategory Security -GroupScope Universal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"

# Create local admin groups

New-ADGroup -Name "LocalAdmin_Servers" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "LocalAdmin_Workstations" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"

# Create root OU admin group

New-ADGroup -Name "OUAdmin_LAB" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"

# Create subOU admin groups

foreach ($OU in $OUs) {
    New-ADGroup -Name "OUAdmin_LAB_$($OU)" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"
}

# Delegate root OU permissions

$OU = "AD:\OU=LAB,DC=lab,DC=ajf8729,DC=com"
$Group = Get-ADGroup -Identity "OUAdmin_LAB"
$SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $Group.SID
$ACL = Get-Acl -Path $OU
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID,"GenericAll","Allow",1
$ACL.AddAccessRule($ACE)
Set-Acl -Path $OU -AclObject $ACL

# Delegate subOU permissions

foreach ($OU in $OUs) {
    $subOU = "AD:\OU=$($OU),OU=LAB,DC=lab,DC=ajf8729,DC=com"
    $Group = Get-ADGroup -Identity "OUAdmin_LAB_$($OU)"
    $SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $Group.SID
    $ACL = Get-Acl -Path $subOU
    $ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID,"GenericAll","Allow",1
    $ACL.AddAccessRule($ACE)
    Set-Acl -Path $subOU -AclObject $ACL
}

# Grant OU admin access

Add-ADGroupMember -Identity "OUAdmin_LAB" -Members (Get-ADGroup -Identity "RBAC_InfrastructureAdmins")
Add-ADGroupMember -Identity "OUAdmin_LAB_Autopilot" -Members (Get-ADGroup -Identity "RBAC_WorkstationAdmins")
Add-ADGroupMember -Identity "OUAdmin_LAB_Kiosks" -Members (Get-ADGroup -Identity "RBAC_WorkstationAdmins")
Add-ADGroupMember -Identity "OUAdmin_LAB_Workstations" -Members (Get-ADGroup -Identity "RBAC_WorkstationAdmins")
Add-ADGroupMember -Identity "OUAdmin_LAB_Servers" -Members (Get-ADGroup -Identity "RBAC_ServerAdmins")
Add-ADGroupMember -Identity "OUAdmin_LAB_Staging" -Members (Get-ADGroup -Identity "RBAC_WorkstationAdmins")

# Grant local admin access

Add-ADGroupMember -Identity "LocalAdmin_Servers" -Members (Get-ADGroup -Identity "RBAC_InfrastructureAdmins")
Add-ADGroupMember -Identity "LocalAdmin_Servers" -Members (Get-ADGroup -Identity "RBAC_ServerAdmins")
Add-ADGroupMember -Identity "LocalAdmin_Workstations" -Members (Get-ADGroup -Identity "RBAC_WorkstationAdmins")

# Create user accounts

New-ADUser -Name "ajf-da" -SamAccountName "ajf-da" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (DA)" -Path "OU=T0,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-da@lab.ajf8729.com" -AccountPassword $DAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf-sa" -SamAccountName "ajf-sa" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (SA)" -Path "OU=Administrators,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-sa@lab.ajf8729.com" -AccountPassword $SAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf-wa" -SamAccountName "ajf-wa" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (WA)" -Path "OU=Administrators,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-wa@lab.ajf8729.com" -AccountPassword $WAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf" -SamAccountName "ajf" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez" -Path "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf@lab.ajf8729.com" -AccountPassword $Password -PasswordNeverExpires $true -Enabled $true

# Add users to necessary groups

Add-ADGroupMember -Identity "Domain Admins" -Members (Get-ADUser -Identity "ajf-da")
Add-ADGroupMember -Identity "Enterprise Admins" -Members (Get-ADUser -Identity "ajf-da")
Add-ADGroupMember -Identity "Schema Admins" -Members (Get-ADUser -Identity "ajf-da")

Add-ADGroupMember -Identity "RBAC_InfrastructureAdmins" -Members (Get-ADUser -Identity "ajf-sa")

Add-ADGroupMember -Identity "RBAC_WorkstationAdmins" -Members (Get-ADUser -Identity "ajf-wa")

# Create KDS root key

Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours((-10)))

# Rename default AD site

Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter "objectClass -eq 'site' -and name -eq 'Default-First-Site-Name'" | Rename-ADObject -NewName "LAB"

# Create AD subnet

New-ADReplicationSubnet -Name "172.20.1.0/24" -Site "LAB"

# Enable AD recycling bin

Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "lab.ajf8729.com" -Confirm:$false

# Redirect default Computers and Users containers

redircmp.exe "OU=Staging,OU=LAB,DC=lab,DC=ajf8729,DC=com" | Out-Null
redirusr.exe "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" | Out-Null

#Create ConfigMgr objects

New-ADOrganizationalUnit -Name "CM" -Path "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -Description "ConfigMgr"

New-ADComputer -Name "LABCM01" -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"

New-ADGroup -Name "CM_Servers" -GroupCategory Security -GroupScope Universal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "CM_Admins" -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "CM_SQL_Admins" -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"

Add-ADGroupMember -Identity "CM_Servers" -Members (Get-ADComputer -Identity "LABCM01")
Add-ADGroupMember -Identity "CM_Admins" -Members (Get-ADGroup -Identity "CM_Servers")
Add-ADGroupMember -Identity "CM_Admins" -Members (Get-ADGroup -Identity "RBAC_InfrastructureAdmins")
Add-ADGroupMember -Identity "CM_SQL_Admins" -Members (Get-ADGroup -Identity "CM_Admins")

New-ADServiceAccount -Name "svc_CM_SQL" -SamAccountName "svc_CM_SQL" -DNSHostName "labcm01.lab.ajf8729.com" -KerberosEncryptionType AES128,AES256 -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -PrincipalsAllowedToRetrieveManagedPassword (Get-ADGroup -Identity "CM_Servers")

New-ADObject -Name "System Management" -Type Container -Path "CN=System,DC=lab,DC=ajf8729,DC=com"

$CN = "AD:\CN=System Management,CN=System,DC=lab,DC=ajf8729,DC=com"
$Group = Get-ADGroup -Identity "CM_Admins"
$SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $Group.SID
$ACL = Get-Acl -Path $CN
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID,"GenericAll","Allow",1
$ACL.AddAccessRule($ACE)
Set-Acl -Path $CN -AclObject $ACL

# Create central store

New-Item -Path "C:\Windows\SYSVOL\domain\Policies" -Name PolicyDefinitions -ItemType Directory | Out-Null
Copy-Item -Path "C:\Windows\PolicyDefinitions\*" -Destination "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions\" -Recurse

# Create GPOs

$GPONames = (
    "lab.ajf8729.com",
    "DC - Default Security Policy",
    "All - Default Security Policy",
    "Autopilot - Default Security Policy",
    "Kiosk - Default Security Policy",
    "Server - Default Security Policy",
    "Server - ConfigMgr",
    "Staging - Default Security Policy",
    "User - Default Security Policy",
    "Workstation - Default Security Policy"
)

foreach ($GPOName in $GPONames) {
    New-GPO -Name $GPOName | Out-Null
}

# Set GPO permissions

$GPONames = (
    "All - Default Security Policy",
    "Autopilot - Default Security Policy",
    "Kiosk - Default Security Policy",
    "Server - Default Security Policy",
    "Server - ConfigMgr",
    "Staging - Default Security Policy",
    "User - Default Security Policy",
    "Workstation - Default Security Policy"
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName "RBAC_InfrastructureAdmins" -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity | Out-Null
}

$GPONames = (
    "Server - Default Security Policy",
    "Server - ConfigMgr"
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName "RBAC_ServerAdmins" -TargetType Group -PermissionLevel GpoEdit | Out-Null
}

$GPONames = (
    "Autopilot - Default Security Policy",
    "Kiosk - Default Security Policy",
    "Staging - Default Security Policy",
    "Workstation - Default Security Policy"
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName "RBAC_WorkstationAdmins" -TargetType Group -PermissionLevel GpoEdit | Out-Null
}

# Link GPOs

New-GPLink -Name "lab.ajf8729.com" -Target "DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "DC - Default Security Policy" -Target "OU=Domain Controllers,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "All - Default Security Policy" -Target "OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "Server - Default Security Policy" -Target "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "Server - ConfigMgr" -Target "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "Autopilot - Default Security Policy" -Target "OU=Autopilot,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Workstation - Default Security Policy" -Target "OU=Autopilot,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null

New-GPLink -Name "Kiosk - Default Security Policy" -Target "OU=Kiosks,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Workstation - Default Security Policy" -Target "OU=Kiosks,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null

New-GPLink -Name "Staging - Default Security Policy" -Target "OU=Staging,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Workstation - Default Security Policy" -Target "OU=Staging,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null

New-GPLink -Name "Workstation - Default Security Policy" -Target "OU=Workstations,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "User - Default Security Policy" -Target "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
