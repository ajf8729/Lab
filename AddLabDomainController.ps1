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
    [string]$DomainUsername,
    [Parameter(Mandatory = $true)]
    [string]$DomainPassword,
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [Parameter(Mandatory = $true)]
    [string]$SafeModeAdministratorPassword
)

$VMName = "$LabName-$VMHostname"

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)

$Session = New-PSSession -VMName $VMName -Credential $Credential

Invoke-Command -Session $Session -ScriptBlock {Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools}

$SecureSafeModeAdministratorPassword = ConvertTo-SecureString -String $SafeModeAdministratorPassword -AsPlainText -Force
$SecureDomainPassword = ConvertTo-SecureString -String $DomainPassword -AsPlainText -Force
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DomainUsername, $SecureDomainPassword)

$ScriptBlock = {
    Import-Module -Name ADDSDeployment

    $Parameters = @{
        DomainName                    = $using:DomainName
        Credential                    = $using:DomainCredential
        DatabasePath                  = 'C:\Windows\NTDS'
        LogPath                       = 'C:\Windows\NTDS'
        SysvolPath                    = 'C:\Windows\SYSVOL'
        SafeModeAdministratorPassword = $using:SecureSafeModeAdministratorPassword
        InstallDns                    = $true
        NoRebootOnCompletion          = $false
        Confirm                       = $false
        Verbose                       = $true
    }

    Install-ADDSDomainController @Parameters
}

Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
