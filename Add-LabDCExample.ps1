$Parameters = @{
    LabName                       = 'LAB'
    VMHostname                    = 'LABDC01B'
    Username                      = 'LAB\Administrator'
    Password                      = '9fc8b485-2fac-4807-a71e-e8767b79a859'
    DomainUsername                = 'LAB\Administrator'
    DomainPassword                = '9fc8b485-2fac-4807-a71e-e8767b79a859'
    DomainName                    = 'lab.ajf8729.net'
    SafeModeAdministratorPassword = '9fc8b485-2fac-4807-a71e-e8767b79a859'
}

.\Add-LabDC.ps1 @Parameters
