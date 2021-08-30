$GPONames = (
    "lab.ajf8729.com",
    "DC - Default Security Policy",
    "All - Default Security Policy",
    "Server - Default Security Policy",
    "Server - ConfigMgr",
    "Client - Default Security Policy",
    "User - Default Security Policy"
)

foreach ($GPOName in $GPONames) {
    New-GPO -Name $GPOName | Out-Null
}

$GPONames = (
    "All - Default Security Policy",
    "Server - Default Security Policy",
    "Server - ConfigMgr",
    "Client - Default Security Policy",
    "User - Default Security Policy"
)

foreach ($GPOName in $GPONames) {
    Set-GPPermission -Name $GPOName -TargetName "OUAdmin_LAB" -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity | Out-Null
}

New-GPLink -Name "lab.ajf8729.com" -Target "DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1
New-GPLink -Name "DC - Default Security Policy" -Target "OU=Domain Controllers,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "All - Default Security Policy" -Target "OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Server - Default Security Policy" -Target "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Server - ConfigMgr" -Target "OU=CM,OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "Client - Default Security Policy" -Target "OU=Clients,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
New-GPLink -Name "User - Default Security Policy" -Target "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null
