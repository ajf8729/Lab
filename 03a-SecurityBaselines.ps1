[CmdletBinding()]
Param(
)

# Modules

Import-Module -Name ActiveDirectory

# Variables

$BaseURL = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8"

$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$DomainNetBIOSName       = (Get-ADDomain).NetBIOSName
$RootOUDistinguishedName = "OU=$($DomainNetBIOSName),$($DomainDistinguishedName)"

# Download baselines

New-Item -Path $env:TEMP -Name baselinetemp -ItemType Directory

Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Windows%2011%20Security%20Baseline.zip"                   -OutFile "$env:TEMP\baselinetemp\Windows11SecurityBaseline.zip"
Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Windows%20Server%202022%20Security%20Baseline.zip"        -OutFile "$env:TEMP\baselinetemp\WindowsServer2022SecurityBaseline.zip"
Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Microsoft%20365%20Apps%20for%20Enterprise-2104-FINAL.zip" -OutFile "$env:TEMP\baselinetemp\Microsoft365AppsforEnterprise-2104-FINAL.zip"
Invoke-WebRequest -UseBasicParsing -Uri "$($BaseURL)/Microsoft%20Edge%20v95%20Security%20Baseline.zip"         -OutFile "$env:TEMP\baselinetemp\MicrosoftEdgev95SecurityBaseline.zip"

# Extract baselines

(Get-ChildItem -Path "$env:TEMP\baselinetemp\*.zip").Name | ForEach-Object {
    Expand-Archive -Path $env:TEMP\baselinetemp\$_ -DestinationPath .
}

# Import baselines

(Get-ChildItem -Directory).Name | ForEach-Object {
    .$env:TEMP\baselinetemp\$_\Scripts\Baseline-ADImport.ps1
}

# Link GPOs

New-GPLink -Name "MSFT Windows Server 2022 - Domain Controller"  -Target "OU=Domain Controllers,$DomainDistinguishedName" -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name "MSFT Windows Server 2022 - Defender Antivirus" -Target "OU=Domain Controllers,$DomainDistinguishedName" -LinkEnabled Yes -Enforced No -Order 3
New-GPLink -Name "MSFT Windows 10 21H1 - User"                   -Target "OU=T0,$DomainDistinguishedName"                 -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name "MSFT Windows 10 21H1 - User"                   -Target "OU=Administrators,$RootOUDistinguishedName"     -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name "MSFT Windows 10 21H1 - Computer"               -Target "OU=Autopilot,$RootOUDistinguishedName"          -LinkEnabled Yes -Enforced No -Order 3
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus"     -Target "OU=Autopilot,$RootOUDistinguishedName"          -LinkEnabled Yes -Enforced No -Order 4
New-GPLink -Name "MSFT Windows 10 21H1 - Computer"               -Target "OU=Kiosks,$RootOUDistinguishedName"             -LinkEnabled Yes -Enforced No -Order 3
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus"     -Target "OU=Kiosks,$RootOUDistinguishedName"             -LinkEnabled Yes -Enforced No -Order 4
New-GPLink -Name "MSFT Windows Server 2022 - Member Server"      -Target "OU=Servers,$RootOUDistinguishedName"            -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name "MSFT Windows Server 2022 - Defender Antivirus" -Target "OU=Servers,$RootOUDistinguishedName"            -LinkEnabled Yes -Enforced No -Order 3
New-GPLink -Name "MSFT Windows 10 21H1 - Computer"               -Target "OU=Staging,$RootOUDistinguishedName"            -LinkEnabled Yes -Enforced No -Order 3
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus"     -Target "OU=Staging,$RootOUDistinguishedName"            -LinkEnabled Yes -Enforced No -Order 4
New-GPLink -Name "MSFT Windows 10 21H1 - User"                   -Target "OU=Users,$RootOUDistinguishedName"              -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name "MSFT Windows 10 21H1 - Computer"               -Target "OU=Workstations,$RootOUDistinguishedName"       -LinkEnabled Yes -Enforced No -Order 2
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus"     -Target "OU=Workstations,$RootOUDistinguishedName"       -LinkEnabled Yes -Enforced No -Order 3
