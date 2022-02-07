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
    [string]$DomainName
)

$VMName = "$LabName-$VMHostname"

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)

$DomainCredential = Get-Credential -Message "Enter appropriate credentials to perform domain join (domain admin, server admin, or workstation admin)"

$Session = New-PSSession -VMName $VMName -Credential $Credential

Invoke-Command -Session $Session -ScriptBlock {Add-Computer -DomainName $using:DomainName -DomainCredential $using:DomainCredential -Restart}
