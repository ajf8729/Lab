[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    [Parameter(Mandatory=$true)]
    [string]$DomainNetbiosName
)

$SafeModeAdministratorPassword = Read-Host -Prompt "Enter the safe mode administrator password" -AsSecureString

Install-WindowsFeature -Name AD-Domain-Services,DNS -IncludeManagementTools

Import-Module -Name ADDSDeployment

$Parameters = @{
    DomainName                    = $DomainName;
    DomainNetbiosName             = $DomainNetbiosName;
    ForestMode                    = 'WinThreshold';
    DomainMode                    = 'WinThreshold';
    DatabasePath                  = 'C:\Windows\NTDS';
    LogPath                       = 'C:\Windows\NTDS';
    SysvolPath                    = 'C:\Windows\SYSVOL';
    SafeModeAdministratorPassword = $SafeModeAdministratorPassword;
    InstallDns                    = $true;
    CreateDnsDelegation           = $false;
    NoRebootOnCompletion          = $false;
    Confirm                       = $false;
    Verbose                       = $true
}

Install-ADDSForest @Parameters
