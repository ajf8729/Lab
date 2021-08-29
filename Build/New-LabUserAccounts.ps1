Import-Module -Name ActiveDirectory

$DAPassword = Read-Host -Prompt "Enter domain admin account password" -AsSecureString
$SAPassword = Read-Host -Prompt "Enter server admin account password" -AsSecureString
$WAPassword = Read-Host -Prompt "Enter workstation admin account password" -AsSecureString
$Password = Read-Host -Prompt "Enter user account password" -AsSecureString

New-ADUser -Name "ajf-da" -SamAccountName "ajf-da" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (DA)" -Path "OU=T0,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-da@lab.ajf8729.com" -AccountPassword $DAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf-sa" -SamAccountName "ajf-sa" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (SA)" -Path "OU=Administrators,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-sa@lab.ajf8729.com" -AccountPassword $SAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf-wa" -SamAccountName "ajf-wa" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez (WA)" -Path "OU=Administrators,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf-wa@lab.ajf8729.com" -AccountPassword $WAPassword -PasswordNeverExpires $true -Enabled $true
New-ADUser -Name "ajf" -SamAccountName "ajf" -GivenName "Anthony" -Initials "J" -Surname "Fontanez" -DisplayName "Anthony J. Fontanez" -Path "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" -UserPrincipalName "ajf@lab.ajf8729.com" -AccountPassword $Password -PasswordNeverExpires $true -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members "ajf-da"
Add-ADGroupMember -Identity "Enterprise Admins" -Members "ajf-da"
Add-ADGroupMember -Identity "Schema Admins" -Members "ajf-da"
