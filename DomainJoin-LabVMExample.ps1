$Parameters = @{
    LabName    = 'LAB'
    VMHostname = 'LABDC01B'
    Username   = 'Administrator'
    Password   = '9fc8b485-2fac-4807-a71e-e8767b79a859'
    DomainName = 'lab.ajf8729.net'
}

.\DomainJoin-LabVM.ps1 @Parameters
