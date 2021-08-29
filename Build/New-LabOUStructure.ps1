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
$ACE = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule $SID,"GenericAll","Allow"
$ACL.AddAccessRule($ACE)
Set-Acl -Path $OU -AclObject $ACL
