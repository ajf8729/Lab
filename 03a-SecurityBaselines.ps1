New-GPLink -Name "MSFT Windows Server 2022 - Domain Controller" -Target "OU=Domain Controllers,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null
New-GPLink -Name "MSFT Windows Server 2022 - Defender Antivirus" -Target "OU=Domain Controllers,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 3 | Out-Null

New-GPLink -Name "MSFT Windows Server 2022 - Member Server" -Target "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null
New-GPLink -Name "MSFT Windows Server 2022 - Defender Antivirus" -Target "OU=Servers,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 3 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - Computer" -Target "OU=Autopilot,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 3 | Out-Null
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus" -Target "OU=Autopilot,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 4 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - Computer" -Target "OU=Staging,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 3 | Out-Null
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus" -Target "OU=Staging,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 4 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - Computer" -Target "OU=Workstations,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null
New-GPLink -Name "MSFT Windows 10 21H1 - Defender Antivirus" -Target "OU=Workstations,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 3 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - User" -Target "OU=T0,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - User" -Target "OU=Administrators,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 1 | Out-Null

New-GPLink -Name "MSFT Windows 10 21H1 - User" -Target "OU=Users,OU=LAB,DC=lab,DC=ajf8729,DC=com" -LinkEnabled Yes -Enforced No -Order 2 | Out-Null
