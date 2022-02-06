[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [string]$Password,
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [Parameter(Mandatory = $true)]
    [string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)]
    [string]$SafeModeAdministratorPassword
)

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)

$Session = New-PSSession -VMName $VMName -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {Rename-Computer -NewName AGWDC01A -Restart}
Start-Sleep -Seconds 30

$Session = New-PSSession -VMName $VMName -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {New-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IPAddress 172.30.1.81 -PrefixLength 24 -DefaultGateway 172.30.1.1}
Invoke-Command -Session $Session -ScriptBlock {Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 172.30.1.1}
Invoke-Command -Session $Session -ScriptBlock {Set-TimeZone -Id 'Eastern Standard Time'}
Invoke-Command -Session $Session -ScriptBlock {Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools}

$SecureSafeModeAdministratorPassword = ConvertTo-SecureString -String $SafeModeAdministratorPassword -AsPlainText -Force

$ScriptBlock = {
    Import-Module -Name ADDSDeployment

    $Parameters = @{
        DomainName                    = $using:DomainName;
        DomainNetbiosName             = $using:DomainNetBIOSName;
        ForestMode                    = 'WinThreshold';
        DomainMode                    = 'WinThreshold';
        DatabasePath                  = 'C:\Windows\NTDS';
        LogPath                       = 'C:\Windows\NTDS';
        SysvolPath                    = 'C:\Windows\SYSVOL';
        SafeModeAdministratorPassword = $using:SecureSafeModeAdministratorPassword;
        InstallDns                    = $true;
        CreateDnsDelegation           = $false;
        NoRebootOnCompletion          = $false;
        Confirm                       = $false;
        Verbose                       = $true
    }

    Install-ADDSForest @Parameters
}

Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
