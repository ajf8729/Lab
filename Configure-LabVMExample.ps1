$Parameters = @{
    LabName        = 'LAB'
    VMHostname     = 'LABDC01B'
    Username       = 'Administrator'
    Password       = '9fc8b485-2fac-4807-a71e-e8767b79a859'
    IPAddress      = '172.30.102.3'
    PrefixLength   = 24
    DefaultGateway = '172.30.102.1'
    DNSServer      = '172.30.102.2'
    TimeZoneID     = 'Eastern Standard Time'
}

.\Configure-LabVM.ps1 @Parameters
