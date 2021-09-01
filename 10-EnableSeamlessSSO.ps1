Import-Module -FullyQualifiedName "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1"

New-AzureADSSOAuthenticationContext
Enable-AzureADSSOForest

Get-ADComputer -Identity AZUREADSSOACC | Move-ADObject -TargetPath "OU=T0,DC=lab,DC=ajf8729,DC=com"
