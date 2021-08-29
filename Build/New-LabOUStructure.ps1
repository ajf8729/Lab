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
