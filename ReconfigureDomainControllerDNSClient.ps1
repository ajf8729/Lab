[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$LabName,
    [Parameter(Mandatory = $true)]
    [string]$DCHostnameA,
    [Parameter(Mandatory = $true)]
    [string]$DCHostnameB,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [string]$Password
)

$DCA = "$LabName-$DCHostnameA"
$DCB = "$LabName-$DCHostnameB"

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)

$SessionA = New-PSSession -VMName $DCA -Credential $Credential
$SessionB = New-PSSession -VMName $DCB -Credential $Credential

$ScriptBlockA = {
    $DCBIPAddress = (Resolve-DnsName -Name $using:DCHostnameB -Type A).IPAddress
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $DCBIPAddress, 127.0.0.1
}

$ScriptBlockB = {
    $DCAIPAddress = (Resolve-DnsName -Name $using:DCHostnameA -Type A).IPAddress
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $DCAIPAddress, 127.0.0.1
}

Invoke-Command -Session $SessionA -ScriptBlock $ScriptBlockA
Invoke-Command -Session $SessionB -ScriptBlock $ScriptBlockB
