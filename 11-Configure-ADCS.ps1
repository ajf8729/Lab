Install-WindowsFeature -Name ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools

Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -CACommonName "AJF8729 Lab Root Certificate Authority" -CADistinguishedNameSuffix "DC=lab,DC=ajf8729,DC=com" -ValidityPeriodUnits 5 -ValidityPeriod Years -DatabaseDirectory "C:\Windows\system32\CertLog" -LogDirectory "C:\Windows\system32\CertLog" -Confirm:$false | Out-Null
Install-AdcsWebEnrollment -Confirm:$false | Out-Null
