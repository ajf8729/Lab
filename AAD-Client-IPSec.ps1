# Configure Default Main Mode Crypto Set
# {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE1}

$Proposal = New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA256 -KeyExchange DH19
New-NetIPsecMainModeCryptoSet -DisplayName "Default Main Mode Crypto Set" -Proposal $Proposal -ForceDiffieHellman $true -Default | Out-Null

# Configure Default Quick Mode Crypto Set
# {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE2}

$Proposal = New-NetIPsecQuickModeCryptoProposal -Encapsulation ESP -Encryption AESGCM256 -ESPHash AESGMAC256
New-NetIPsecQuickModeCryptoSet -DisplayName "Default Quick Mode Crypto Set" -Proposal $Proposal -Default | Out-Null

# Configure Default Phase 1 Auth Set
# {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}

$Proposal = New-NetIPsecAuthProposal -Machine -Cert -Authority "DC=com, DC=ajf8729, DC=ad, CN=AJF8729 Root Certificate Authority" -AuthorityType Root
New-NetIPsecPhase1AuthSet -DisplayName "Default IPSec Phase 1 Auth Set" -Proposal $Proposal -Default | Out-Null

# Configure Default Phase 2 Auth Set
# {E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE4}

$Proposal = New-NetIPsecAuthProposal -User -Kerberos
New-NetIPsecPhase2AuthSet -DisplayName "Default IPSec Phase 2 Auth Set" -Proposal $Proposal -Default | Out-Null

# Configure User Kerberos OR Anonymous Phase 2 Auth Set

$Proposal1 = New-NetIPsecAuthProposal -User -Kerberos
$Proposal2 = New-NetIPsecAuthProposal -Anonymous
New-NetIPsecPhase2AuthSet -Name "User Kerberos OR Anonymous" -DisplayName "User Kerberos OR Anonymous" -Proposal $Proposal1,$Proposal2 | Out-Null

# Create "Domain Controllers" IPSec Rule

New-NetIPsecRule -Name "Domain Controllers" -DisplayName "Domain Controllers" -InboundSecurity Request -OutboundSecurity Request -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -Phase2AuthSet "User Kerberos OR Anonymous" -RemoteAddress 172.20.1.13,172.20.1.19 | Out-Null

# Create "ADCM01" IPSec Rule

New-NetIPsecRule -Name "ADCM01" -DisplayName "ADCM01" -InboundSecurity Request -OutboundSecurity Request -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -Phase2AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE4}" -RemoteAddress 172.20.1.16 -Protocol TCP -RemotePort 445 | Out-Null

#Create "CORE" IPSec Rule

New-NetIPsecRule -Name "CORE" -DisplayName "CORE" -InboundSecurity Require -OutboundSecurity Require -Phase1AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}" -Phase2AuthSet "{E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE4}" -RemoteAddress 172.20.1.20 -Protocol TCP -RemotePort 8080 | Out-Null
