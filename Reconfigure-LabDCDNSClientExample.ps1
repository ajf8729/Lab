$Parameters = @{
    LabName     = 'LAB'
    DCHostnameA = 'LABDC01A'
    DCHostnameB = 'LABDC01B'
    Username    = 'LAB\Administrator'
    Password    = '9fc8b485-2fac-4807-a71e-e8767b79a859'
}

.\Reconfigure-LabDCDNSClient.ps1 @Parameters
