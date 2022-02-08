[CmdletBinding()]
Param(
)

# Modules

Import-Module -Name ActiveDirectory

# Variables

$BaseURL = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8'

$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$DomainNetBIOSName = (Get-ADDomain).NetBIOSName
$RootOUDistinguishedName = "OU=$($DomainNetBIOSName),$($DomainDistinguishedName)"

# Save current path
$CurrentPath = (Get-Location).Path

# Download baselines
New-Item -Path $env:TEMP -Name baselinetemp -ItemType Directory
Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Windows%2011%20Security%20Baseline.zip" -OutFile "$env:TEMP\baselinetemp\Windows11SecurityBaseline.zip"
Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Windows%20Server%202022%20Security%20Baseline.zip" -OutFile "$env:TEMP\baselinetemp\WindowsServer2022SecurityBaseline.zip"

# Extract baselines
(Get-ChildItem -Path "$env:TEMP\baselinetemp\*.zip").Name | ForEach-Object {
    Expand-Archive -Path $env:TEMP\baselinetemp\$_ -DestinationPath $env:TEMP\baselinetemp
}

# Copy templates to central store
(Get-ChildItem -Path $env:TEMP\baselinetemp -Directory).Name | ForEach-Object {
    if (Test-Path -Path $env:TEMP\baselinetemp\$_\Templates\) {
        Set-Location -Path $env:TEMP\baselinetemp\$_\Templates\
        Copy-Item -Path '*' -Destination 'C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions\' -Recurse -Force
    }
}

# Import baselines
(Get-ChildItem -Path $env:TEMP\baselinetemp -Directory).Name | ForEach-Object {
    Set-Location -Path $env:TEMP\baselinetemp\$_\Scripts\
    .\Baseline-ADImport.ps1
}

# Link GPOs

# Domain Controllers OU
New-GPLink -Name 'MSFT Windows Server 2022 - Domain Controller' -Target "OU=Domain Controllers,$DomainDistinguishedName"
New-GPLink -Name 'MSFT Windows Server 2022 - Domain Controller Virtualization Based Security' -Target "OU=Domain Controllers,$DomainDistinguishedName"
New-GPLink -Name 'MSFT Windows Server 2022 - Defender Antivirus' -Target "OU=Domain Controllers,$DomainDistinguishedName"
# Move "Default Domain Controllers Policy" to last
$DCLinkCount = ((Get-GPInheritance -Target "OU=Domain Controllers,$DomainDistinguishedName").GpoLinks).Count
Set-GPLink -Name 'Default Domain Controllers Policy' -Target "OU=Domain Controllers,$DomainDistinguishedName" -Order $DCLinkCount

# T0 OU
New-GPLink -Name 'MSFT Windows 11 - User' -Target "OU=T0,$DomainDistinguishedName"

# Administrators OU
New-GPLink -Name 'MSFT Windows 11 - User' -Target "OU=Administrators,$RootOUDistinguishedName"

# Autopilot OU
New-GPLink -Name 'MSFT Windows 11 - Computer' -Target "OU=Autopilot,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Credential Guard' -Target "OU=Autopilot,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Defender Antivirus' -Target "OU=Autopilot,$RootOUDistinguishedName"

# Kiosks OU
New-GPLink -Name 'MSFT Windows 11 - Computer' -Target "OU=Kiosks,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Credential Guard' -Target "OU=Kiosks,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Defender Antivirus' -Target "OU=Kiosks,$RootOUDistinguishedName"

# Servers OU
New-GPLink -Name 'MSFT Windows Server 2022 - Member Server' -Target "OU=Servers,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows Server 2022 - Member Server Credential Guard' -Target "OU=Servers,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows Server 2022 - Defender Antivirus' -Target "OU=Servers,$RootOUDistinguishedName"

# Staging OU
New-GPLink -Name 'MSFT Windows 11 - Computer' -Target "OU=Staging,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Credential Guard' -Target "OU=Staging,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Defender Antivirus' -Target "OU=Staging,$RootOUDistinguishedName"

# Users OU
New-GPLink -Name 'MSFT Windows 11 - User' -Target "OU=Users,$RootOUDistinguishedName"

# Workstations OU
New-GPLink -Name 'MSFT Windows 11 - Computer' -Target "OU=Workstations,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Credential Guard' -Target "OU=Workstations,$RootOUDistinguishedName"
New-GPLink -Name 'MSFT Windows 11 - Defender Antivirus' -Target "OU=Workstations,$RootOUDistinguishedName"

# Revert to saved path
Set-Location -Path $CurrentPath
