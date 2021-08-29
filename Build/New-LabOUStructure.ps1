Import-Module -Name ActiveDirectory

New-ADOrganizationalUnit -Name "LAB" -Path "DC=lab,DC=ajf8729,DC=com" -Description "LAB Root OU"
New-ADOrganizationalUnit -Name "T0" -Path "DC=lab,DC=ajf8729,DC=com" -Description "Tier 0 Objects"

$OUs = (
    "Administrators",
    "Autopilot",
    "Clients",
    "Groups",
    "Servers",
    "Staging",
    "Users"
)

foreach ($OU in $OUs) {
    New-ADOrganizationalUnit -Name $OU -Path "OU=LAB,DC=lab,DC=ajf8729,DC=com" -Description "LAB $OU"
}

New-ADGroup -Name "OUAdmin_LAB" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Groups,OU=LAB,DC=lab,DC=ajf8729,DC=com"

$OU = "AD:\OU=LAB,DC=lab,DC=ajf8729,DC=com"
$Group = Get-ADGroup -Identity "OUAdmin_LAB"
$SID = New-Object -TypeName System.Security.Principal.SecurityIdentifier $Group.SID
$ACL = Get-Acl -Path $OU
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID,"GenericAll","Allow",1
$ACL.AddAccessRule($ACE)
Set-Acl -Path $OU -AclObject $ACL

New-ADOrganizationalUnit -Name "CM" -Path "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -Description "ConfigMgr"

New-ADComputer -Name "LABCM01" -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"

New-ADGroup -Name "CM_Servers" -GroupCategory Security -GroupScope Universal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "CM_Admins" -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"
New-ADGroup -Name "CM_SQL_Admins" -GroupCategory Security -GroupScope DomainLocal -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com"

Add-ADGroupMember -Identity "CM_Servers" -Members (Get-ADComputer -Identity "LABCM01")
Add-ADGroupMember -Identity "CM_Admins" -Members (Get-ADGroup -Identity "CM_Servers")
Add-ADGroupMember -Identity "CM_SQL_Admins" -Members (Get-ADGroup -Identity "CM_Admins")

New-ADServiceAccount -Name "svc_CM_SQL" -SamAccountName "svc_CM_SQL" -DNSHostName "labcm01.lab.ajf8729.com" -KerberosEncryptionType AES128,AES256 -Path "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -PrincipalsAllowedToRetrieveManagedPassword (Get-ADGroup -Identity "CM_Servers")
