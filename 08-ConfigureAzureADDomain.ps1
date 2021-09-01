Import-Module 
Import-Module -Name MSOnline

Connect-AzureAD
Connect-MsolService

New-AzureADDomain -Name "lab.ajf8729.com"
Get-MsolDomainVerificationDns -DomainName "lab.ajf8729.com"

while ($null -eq (Resolve-DnsName -Name lab.ajf8729.com -Type TXT -ErrorAction Ignore | Select-Object -ExpandProperty Strings)) {
    Write-Host -Object "Waiting..."
    Start-Sleep -Seconds 10
}

Confirm-AzureADDomain -Name "lab.ajf8729.com"

Set-AzureADDomain -Name "lab.ajf8729.com" -IsDefault $true
