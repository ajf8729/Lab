Import-Module AdmPwd.PS

Update-AdmPwdADSchema -Verbose

New-ADGroup -Name LAPSAdmin_CORP_Autopilot    -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal
New-ADGroup -Name LAPSAdmin_CORP_Kiosks       -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal
New-ADGroup -Name LAPSAdmin_CORP_Servers      -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal
New-ADGroup -Name LAPSAdmin_CORP_Staging      -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal
New-ADGroup -Name LAPSAdmin_CORP_Workstations -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal
New-ADGroup -Name LAPSAdmin_T0                -Path "OU=Groups,OU=CORP,DC=corp,DC=ajf8729,DC=com" -GroupScope DomainLocal

Set-AdmPwdComputerSelfPermission -Identity "OU=Autopilot,OU=CORP,DC=corp,DC=ajf8729,DC=com"
Set-AdmPwdComputerSelfPermission -Identity "OU=Kiosks,OU=CORP,DC=corp,DC=ajf8729,DC=com"
Set-AdmPwdComputerSelfPermission -Identity "OU=Servers,OU=CORP,DC=corp,DC=ajf8729,DC=com"
Set-AdmPwdComputerSelfPermission -Identity "OU=Staging,OU=CORP,DC=corp,DC=ajf8729,DC=com"
Set-AdmPwdComputerSelfPermission -Identity "OU=Workstations,OU=CORP,DC=corp,DC=ajf8729,DC=com"
Set-AdmPwdComputerSelfPermission -Identity "OU=T0,DC=corp,DC=ajf8729,DC=com"

Set-AdmPwdResetPasswordPermission -Identity "OU=Autopilot,OU=CORP,DC=corp,DC=ajf8729,DC=com"    -AllowedPrincipals CORP\LAPSAdmin_CORP_Autopilot
Set-AdmPwdResetPasswordPermission -Identity "OU=Kiosks,OU=CORP,DC=corp,DC=ajf8729,DC=com"       -AllowedPrincipals CORP\LAPSAdmin_CORP_Kiosks
Set-AdmPwdResetPasswordPermission -Identity "OU=Servers,OU=CORP,DC=corp,DC=ajf8729,DC=com"      -AllowedPrincipals CORP\LAPSAdmin_CORP_Servers
Set-AdmPwdResetPasswordPermission -Identity "OU=Staging,OU=CORP,DC=corp,DC=ajf8729,DC=com"      -AllowedPrincipals CORP\LAPSAdmin_CORP_Staging
Set-AdmPwdResetPasswordPermission -Identity "OU=Workstations,OU=CORP,DC=corp,DC=ajf8729,DC=com" -AllowedPrincipals CORP\LAPSAdmin_CORP_Workstations
Set-AdmPwdResetPasswordPermission -Identity "OU=T0,DC=corp,DC=ajf8729,DC=com"                   -AllowedPrincipals CORP\LAPSAdmin_T0
