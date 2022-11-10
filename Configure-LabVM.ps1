[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$LabName,
    [Parameter(Mandatory = $true)]
    [string]$VMHostname,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [string]$Password,
    [Parameter(Mandatory = $true)]
    [string]$IPAddress,
    [Parameter(Mandatory = $true)]
    [int]$PrefixLength,
    [Parameter(Mandatory = $true)]
    [string]$DefaultGateway,
    [Parameter(Mandatory = $true)]
    [string[]]$DNSServer,
    [Parameter(Mandatory = $true)]
    [string]$TimeZoneID
)

$VMName = "$LabName-$VMHostname"

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)

$Session = New-PSSession -VMName $VMName -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {Rename-Computer -NewName $using:VMHostname -Restart}
Start-Sleep -Seconds 30

$Session = New-PSSession -VMName $VMName -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {New-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IPAddress $using:IPAddress -PrefixLength $using:PrefixLength -DefaultGateway $using:DefaultGateway}
Invoke-Command -Session $Session -ScriptBlock {Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $using:DNSServer}
Invoke-Command -Session $Session -ScriptBlock {Set-TimeZone -Id $using:TimeZoneID}
