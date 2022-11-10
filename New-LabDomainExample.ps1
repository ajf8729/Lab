$Parameters = @{
    LabName                       = 'LAB'
    VMHostname                    = 'LABDC01A'
    Username                      = 'Administrator'
    Password                      = '9fc8b485-2fac-4807-a71e-e8767b79a859'
    DomainName                    = 'lab.ajf8729.net'
    DomainNetBIOSName             = 'LAB'
    SafeModeAdministratorPassword = '9fc8b485-2fac-4807-a71e-e8767b79a859'
}

.\New-LabDomain.ps1 @Parameters
