# IPSec Configuration

# Default Main Mode Crypto Set - {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE1}
$Proposal = New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA256 -KeyExchange DH19
New-NetIPsecMainModeCryptoSet -DisplayName "Default Main Mode Crypto Set" -Proposal $Proposal -ForceDiffieHellman $true -Default | Out-Null

# Default Quick Mode Crypto Set - {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE2}
$Proposal = New-NetIPsecQuickModeCryptoProposal -Encapsulation ESP -Encryption AESGCM256 -ESPHash AESGMAC256
New-NetIPsecQuickModeCryptoSet -DisplayName "Default Quick Mode Crypto Set" -Proposal $Proposal -Default | Out-Null

# Default Phase 1 Auth Set - {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}
$Proposal = New-NetIPsecAuthProposal -Machine -Cert -Authority "DC=com, DC=ajf8729, DC=ad, CN=AJF8729 Root Certificate Authority" -AuthorityType Root
New-NetIPsecPhase1AuthSet -DisplayName "Default IPSec Phase 1 Auth Set" -Proposal $Proposal -Default | Out-Null

# "User Kerberos" Phase 2 Auth Set
$Proposal = New-NetIPsecAuthProposal -User -Kerberos
New-NetIPsecPhase2AuthSet -Name "User Kerberos" -DisplayName "User Kerberos" -Proposal $Proposal | Out-Null

# IPSec Rules

# "Domain Controllers"
New-NetIPsecRule -Name "Domain Controllers" -DisplayName "Domain Controllers" -InboundSecurity Request -OutboundSecurity Request -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -RemoteAddress 172.20.1.13,172.20.1.19 | Out-Null

# "adcm01.ad.ajf8729.com:445"
New-NetIPsecRule -Name "adcm01.ad.ajf8729.com:445" -DisplayName "adcm01.ad.ajf8729.com" -InboundSecurity Request -OutboundSecurity Request -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -Phase2AuthSet "User Kerberos" -RemoteAddress 172.20.1.16 -Protocol TCP -RemotePort 445 | Out-Null

# "apps.ad.ajf8729.com:8080"
New-NetIPsecRule -Name "apps.ad.ajf8729.com:8080" -DisplayName "apps.ad.ajf8729.com" -InboundSecurity Require -OutboundSecurity Require -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -Phase2AuthSet "User Kerberos" -RemoteAddress 172.20.1.21 -Protocol TCP -RemotePort 8080 | Out-Null
