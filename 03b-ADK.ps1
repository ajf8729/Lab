[CmdletBinding()]
Param(
)

$AdkUrl   = "https://download.microsoft.com/download/1/f/d/1fd2291e-c0e9-4ae0-beae-fbbe0fe41a5a/adk/adksetup.exe"
$WinPeUrl = "https://download.microsoft.com/download/5/5/e/55e3e34a-5708-46cd-a90d-92044c29336b/adkwinpeaddons/adkwinpesetup.exe"

New-Item -Path $env:TEMP -Name adktemp -ItemType Directory

Invoke-WebRequest -UseBasicParsing -Uri $AdkUrl   -OutFile "$env:TEMP\adktemp\adksetup.exe"
Invoke-WebRequest -UseBasicParsing -Uri $WinPeUrl -OutFile "$env:TEMP\adktemp\adkwinpesetup.exe"

Start-Process -FilePath .\adksetup.exe -ArgumentList "/layout $env:TEMP\adktemp\ADK /log $env:TEMP\adktemp\ADK.log /quiet"
Wait-Process -Name adksetup

Start-Process -FilePath .\adkwinpesetup.exe -ArgumentList "/layout $env:TEMP\adktemp\WinPE /log $env:TEMP\adktemp\WinPE.log /quiet"
Wait-Process -Name adkwinpesetup
