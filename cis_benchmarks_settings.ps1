#9.3.5 is not understood. was not performed. to be investigated.
#17.3.1 is not implemented. audit policy is not found via "auditpol"
#17.6.2 is not implemented. audit policy is not found via "auditpol"
#17.8.1 is not implemented. subcategory is parsed in wrong way
#18.5.20.1 is not implemented FOR CONVENIENCE!!!.
#18.9.47.5.1.2 is not implemented because it had been implemented in other script (with some
# discrepancies)


if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

function Get-LocalUsersWithGroups {
    Get-LocalUser | ForEach-Object {
        $user = $_.Name
        $groups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name).Name -match $user }
        [PSCustomObject]@{
            UserName = $user
            Groups = ($groups.Name -join ', ')
        }
    }
}


# Function to check and create registry path if missing
function Ensure-RegistryPath {
    param (
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Host "$CisNumber - Registry path not found: $Path. Creating it..." -ForegroundColor Yellow
        try {
            New-Item -Path $Path -Force | Out-Null
        } catch {
            Write-Host "$CisNumber - Failed to create registry path. Error: $_" -ForegroundColor Red
        }
    }
}


# Function to set registry value
function Set-RegistryValue {
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter()]
        [object]$Value
    )

    try {
        if ($Null -eq $Value) {
            # Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
        }
    } catch {
        Write-Error "Failed to set registry value '$Name' at path '$Path'. Error: $_"
    }
}


# Function to verify registry value
function Verify-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [Parameter()]
        [object]$ExpectedValue
    )

    $CurrentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "$CisNumber --- $Path --- $Name is set to $ExpectedValue" -ForegroundColor Green
    } else {
        Write-Host "$CisNumber - Fail" -ForegroundColor Red
    }
}


# $CisNumber = "2.3.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "NoConnectedUser"
# $RegistryValue = 3  # Users can't add or log on with Microsoft accounts

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "!!!" -ForegroundColor red
# }


# # 2.3.1.3
# # Disable the Guest account
# $GuestAccount = "Dguest"
# Write-Host "Disabling the Guest account..." -ForegroundColor Yellow
# Try {
#     Get-LocalUser -Name $GuestAccount | Disable-LocalUser
#     Write-Host "Guest account has been successfully disabled." -ForegroundColor Green
# } Catch {
#     Write-Host "Error: Unable to disable the Guest account. Ensure the script is running as Administrator." -ForegroundColor Red
# }


# # 2.3.1.4
# # Enable the policy: Limit blank password use to console logon only
# Write-Host "Enforcing 'Limit local account use of blank passwords to console logon only' policy..." -ForegroundColor Yellow
# Try {
#     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
#     Write-Host "Policy successfully enforced." -ForegroundColor Green
# } Catch {
#     Write-Host "Error: Unable to enforce the policy. Ensure the script is running as Administrator." -ForegroundColor Red
# }


# # 2.3.1.5
# # Run this script as an Administrator
# # Rename the built-in Administrator account

# # Define the new name for the Administrator account
# $NewAdminName = "Dadmin"  # Change this to your preferred name
# $NewDescription = "System Management Account of my testing pc"
# $AdminAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "*-500" }

# if ($AdminAccount) {
#     # Rename the Administrator account
#     Rename-LocalUser -Name $AdminAccount.Name -NewName $NewAdminName
#     Write-Output "Administrator account renamed to: $NewAdminName"

#     # Update the account description
#     Get-LocalUser -Name $NewAdminName | Set-LocalUser -Description $NewDescription
#     Write-Output "Administrator account description updated."

#     # Confirm the changes
#     Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object Name, Description
# } else {
#     Write-Output "The built-in Administrator account was not found or is disabled."
# }

# # 2.3.1.6
# # Define the new name for the Guest account
# $NewGuestName = "Dguest"  # Change this to your preferred name
# $NewDescription = "Limited access guest account for my notebook"

# $GuestAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "*-501" }

# if ($GuestAccount) {
#     # Rename the Guest account
#     Rename-LocalUser -Name $GuestAccount.Name -NewName $NewGuestName
#     Write-Output "Guest account renamed to: $NewGuestName"

#     # Update the account description
#     Get-LocalUser -Name $NewGuestName | Set-LocalUser -Description $NewDescription
#     Write-Output "Guest account description updated."

#     # Confirm the changes
#     Get-LocalUser | Where-Object { $_.SID -like "*-501" } | Select-Object Name, Description
# } else {
#     Write-Output "The built-in Guest account was not found or is disabled."
# }


# #2.3.2.1
# # Define the registry path and value
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "SCENoApplyLegacyAuditPolicy"
# $RegistryValue = 1
# $CisNumber = "2.3.2.1"

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }















# # 2.3.2.2
# $RegistryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
# $RegistryName = "CrashOnAuditFail"
# $RegistryValue = 0
# $CisNumber = "2.3.2.2"

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.4.1
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
# $RegistryName = "AddPrinterDrivers"
# $RegistryValue = 0
# $CisNumber = "2.3.4.1"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.7.1
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "DisableCAD"
# $RegistryValue = 0
# $CisNumber = "2.3.7.1"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.7.2
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "DontDisplayLastUserName"
# $RegistryValue = 1
# $CisNumber = "2.3.7.2"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# #2.3.7.4
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "InactivityTimeoutSecs"
# $RegistryValue = 600  # Replace with a value of 900 or fewer seconds, but not 0
# $CisNumber = "2.3.7.2"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.7.5
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $MessageTextKey = "LegalNoticeText"
# $MessageTextValue = "Are you sure you want to get access to this supermachine, bitch?"
# $CisNumber = "2.3.7.5"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.7.7
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# $RegistryName = "PasswordExpiryWarning"
# $RegistryValue = 5  # Set the value to a number between 5 and 14 days (e.g., 10 days)
# $CisNumber = "2.3.7.7"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.7.8 - TO BE IMPLEMENTED


# # 2.3.8.1
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
# $RegistryName = "RequireSecuritySignature"
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# $CisNumber = "2.3.8.1"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# #2.3.8.2
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
# $RegistryName = "EnableSecuritySignature"
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# $CisNumber = "2.3.8.2"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.8.3
# # Define the registry path and value
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
# $RegistryName = "EnablePlainTextPassword"
# $RegistryValue = 0  # 0 = Disabled, 1 = Enabled
# $CisNumber = "2.3.8.3"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.9.1
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "AutoDisconnect"
# $RegistryValue = 15  # 15 minutes or fewer
# $CisNumber = "2.3.9.1"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.9.2
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "RequireSecuritySignature"
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# $CisNumber = "2.3.9.2"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.9.3
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "EnableSecuritySignature" # Corrected registry name
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# $CisNumber = "2.3.9.3"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.9.4
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "EnableForcedLogoff"  # Correct registry name
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# $CisNumber = "2.3.9.4"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # 2.3.9.5
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "SmbServerNameHardeningLevel"  # Correct registry name
# $RegistryValue = 1  # 1 = Accept if provided by client, 2 = Required from client, 0 = Off
# $CisNumber = "2.3.9.5"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     Write-Host "$CisNumber - success"
# } catch {
#     Write-Host "$CisNumber - fail" -ForegroundColor red
# }


# # Define parameters
# $CisNumber = "2.3.9.4"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "EnableForcedLogoff"
# $RegistryValue = 1  # 1 = Enabled, 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.9.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
# $RegistryName = "SmbServerNameHardeningLevel"
# $RegistryValue = 1  # 0 = Disabled, 1 = accept if allowed by client, 2 - required from client
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "TurnOffAnonymousBlock"
# $RegistryValue = 1  # 0 = Disabled, 1 = enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "RestrictAnonymousSAM"
# $RegistryValue = 1  # 0 = Disabled, 1 = enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.3"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "RestrictAnonymous"
# $RegistryValue = 1  # 0 = Disabled, 1 = enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.4"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "DisableDomainCreds"
# $RegistryValue = 1  # 0 = Disabled, 1 = enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "EveryoneIncludesAnonymous"
# $RegistryValue = 0  # 0 = Disabled, 1 = enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.6"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "NullSessionPipes"
# $RegistryValue = $Null
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# to be refactored
# $CisNumber = "2.3.10.7"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
# $RegistryName = "Machine"
# $RegistryValue = "System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications/n/rSOFTWARE\Microsoft\Windows NT\CurrentVersion"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.9"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
# $RegistryName = "RestrictNullSessAccess"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.10"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "restrictremotesam"
# $RegistryValue = "O:SYG:SYD:(A;;RC;;;BA)"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.10.12"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "ForceGuest"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "UseMachineId"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
# $RegistryName = "AllowNullSessionFallback"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.3"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
# $RegistryName = "AllowOnlineID"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "NoLMHash"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.6"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
# $RegistryName = "EnableForcedLogoff"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.7"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $RegistryName = "LmCompatibilityLevel"
# $RegistryValue = 5
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.8"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
# $RegistryName = "LDAPClientIntegrity"
# $RegistryValue = 1 # - 1 negotiate signing, 2 - require signing
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.9"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
# $RegistryName = "NTLMMinClientSec"
# $RegistryValue = "0x20080000"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.11.10"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
# $RegistryName = "NTLMMinServerSec"
# $RegistryValue = "0x20080000"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.14.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
# $RegistryName = "ForceKeyProtection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.15.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
# $RegistryName = "ObCaseInsensitive"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.15.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
# $RegistryName = "ProtectionMode"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "FilterAdministratorToken"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.2"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "ConsentPromptBehaviorAdmin"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "2.3.17.3"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "ConsentPromptBehaviorUser"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "2.3.17.4"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "EnableInstallerDetection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.5"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "EnableSecureUIAPaths"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.6"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "EnableLUA"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.7"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "PromptOnSecureDesktop"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "2.3.17.8"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "EnableVirtualization"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.3"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.4"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.6"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.7"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# BE CAREFUL! IF YOU USE WSL FOR WIN, THIS POINT EXECUTION MAY CAUSE IMPOSSIBILITY OF
# OPENSSL USAGE.
# INVESTIGATE https://docs.microsoft.com/en-us/windows/wsl/troubleshooting#wsl-2-errors-when-ics-is-disabled
# FOR TROUBLESHOUTING
# $CisNumber = "5.8"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.9"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.10"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.11"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.12"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.14"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.15"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.16"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.17"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.18"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     $RegistryName = "NoWarningNoElevationOnInstall"
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
    
#     $RegistryName = "UpdatePromptSettings"
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# Stop-Service -Name Spooler -Force
# Set-Service -Name Spooler -StartupType Disabled


# $CisNumber = "5.19"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.21"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.22"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.23"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.24"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.25"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.26"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.27"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.27"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.28"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.29"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.30"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.31"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.32"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.33"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.34"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.35"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.36"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.37"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.38"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.39"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "5.40"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.41"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.42"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.43"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.44"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "5.45"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
# $RegistryName = "Start"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# $RegistryName = "EnableFirewall"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# $RegistryName = "DefaultInboundAction"
# $RegistryValue = 1 # 1 - block, 0 - allow
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# $RegistryName = "DefaultOutboundAction"
# $RegistryValue = 0 # 1 - block, 0 - allow
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# $RegistryName = "DisableNotifications"
# $RegistryValue = 1 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# $RegistryName = "LogFilePath"
# $RegistryValue = "E:\logs\priv_firewall.log" 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# $RegistryName = "LogFileSize"
# $RegistryValue = 32767 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# $RegistryName = "LogDroppedPackets"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.2.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# $RegistryName = "LogSuccessfulConnections"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "EnableFirewall"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "DefaultInboundAction"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "DefaultOutboundAction"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "DisableNotifications"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "AllowLocalPolicyMerge"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# $RegistryName = "AllowLocalIPsecPolicyMerge"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }



# $CisNumber = "9.3.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
# $RegistryName = "LogFilePath"
# $RegistryValue = "E:\logs\pub_firewall.log" 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }



# $CisNumber = "9.3.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
# $RegistryName = "LogFileSize"
# $RegistryValue = 32767 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.9"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
# $RegistryName = "LogDroppedPackets"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "9.3.10"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
# $RegistryName = "LogSuccessfulConnections"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "17.1.1"
# $SubCategory = "�������� ������� ������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.2.1"
# $SubCategory = "���������� ������� ����������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.2.2"
# $SubCategory = "���������� ������� ������������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.2.3"
# $SubCategory = "���������� �������� ��������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.3.1" - to be performed


# $CisNumber = "17.3.2"
# $SubCategory = "�������� ��������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.5.1"
# $SubCategory = "���������� ������� ������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.5.2"
# $SubCategory = "�������� � ������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.5.3"
# $SubCategory = "����� �� �������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.5.4"
# $SubCategory = "���� � �������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.5.5"
# $SubCategory = "������ ������� ����� � ������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.5.6"
# $SubCategory = "����������� ����"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.6.1"
# $SubCategory = "�������� �� ����� �������� �������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.6.3"
# $SubCategory = "������ ������� ������� � �������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "$CisNumber benchmark: '$SubCAtegory' was configured" -ForegroundColor Green


# $CisNumber = "17.6.4"
# $SubCategory = "������� ��������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.7.1"
# $SubCategory = "����� ��������� ��������"
# Write-Host "Configuring Audit Credential Validation..." -ForegroundColor Cyan
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured"


# $CisNumber = "17.7.2"
# $SubCategory = "��������� �������� �����������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "17.7.3"
# $SubCategory = "��������� �������� �������� �����������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan

# $CisNumber = "17.7.4"
# $SubCategory = "��������� �������� ������� ������ MPSSVC"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan

# $CisNumber = "17.7.5"
# $SubCategory = "������ ������� ��������� ��������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "17.9.1"
# $SubCategory = "������� IPSEC"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "17.9.2"
# $SubCategory = "������ ��������� �������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "17.9.3"
# $SubCategory = "��������� ��������� ������������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan

# $CisNumber = "17.9.4"
# $SubCategory = "���������� ������� ������������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan
# $CisNumber = "17.9.4"


# $CisNumber = "17.9.5"
# $SubCategory = "����������� �������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "17.9.5"
# $SubCategory = "����������� �������"
# Write-Host "Configuring Audit Credential Validation..." 
# auditpol /set /subcategory:$SubCategory /success:enable /failure:enable
# Write-Host "'$SubCAtegory' was configured" -ForegroundColor Cyan


# $CisNumber = "18.1.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
# $RegistryName = "NoLockScreenCamera"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.1.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
# $RegistryName = "NoLockScreenSlideshow"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.1.2.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
# $RegistryName = "AllowInputPersonalization"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.1.3"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "AllowOnlineTips"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.3.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb10"
# $RegistryName = "Start"
# $RegistryValue = 4
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation"
# $RegistryName = "DependOnService"
# $RegistryValue = "Bowser","MRxSmb20","NSI"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "18.3.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
# $RegistryName = "SMB1"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.3.3"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
# $RegistryName = "DisableExceptionChainValidation"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.3.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
# $RegistryName = "RestrictDriverInstallationToAdministrators"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.3.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
# $RegistryName = "NodeType"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "18.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# $RegistryName = "AutoAdminLogon"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "18.4.2"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
# $RegistryName = "DisableIPSourceRouting"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.3"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "DisableIPSourceRouting"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.4"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
# $RegistryName = "DisableSavePassword"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }

# $CisNumber = "18.4.5"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "EnableICMPRedirect"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.6"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "KeepAliveTime"
# $RegistryValue = 300000
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.7"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
# $RegistryName = "NoNameReleaseOnDemand"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.8"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "PerformRouterDiscovery"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.9"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
# $RegistryName = "SafeDllSearchMode"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.10"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# $RegistryName = "ScreenSaverGracePeriod"
# $RegistryValue = 5
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.11"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
# $RegistryName = "TcpMaxDataRetransmissions"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.11"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
# $RegistryName = "TcpMaxDataRetransmissions"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.12"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "TcpMaxDataRetransmissions"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.12"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
# $RegistryName = "TcpMaxDataRetransmissions"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.4.13"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
# $RegistryName = "WarningLevel"
# $RegistryValue = 90
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
# $RegistryName = "DoHPolicy"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.4.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
# $RegistryName = "EnableMulticast"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.5.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "EnableFontProviders"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.8.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
# $RegistryName = "AllowInsecureGuestAuth"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.9.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
# $RegistryName = "AllowLLTDIOOnDomain"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "AllowLLTDIOOnPublicNet"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "EnableLLTDIO"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "ProhibitLLTDIOOnPrivateNet"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.9.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
# $RegistryName = "AllowRspndrOnDomain"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "AllowRspndrOnPublicNet"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "EnableRspndr"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "ProhibitRspndrOnPrivateNet"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.10.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
# $RegistryName = "Disabled"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.10.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
# $RegistryName = "Disabled"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.11.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
# $RegistryName = "NC_AllowNetBridge_NLA"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.11.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
# $RegistryName = "NC_ShowSharedAccessUI"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.14.1"
# $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
# Ensure-RegistryPath -Path $RegistryPath

# $hardenedPaths = @{
#     "\\*\NETLOGON" = "RequireMutualAuthentication=1,RequireIntegrity=1"
#     "\\*\SYSVOL" = "RequireMutualAuthentication=1,RequireIntegrity=1"
#     "\\SERVER" = "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"
# }

# foreach ($path in $hardenedPaths.Keys) {
#     $valueName = $path
#     $valueData = $hardenedPaths[$path]
#     Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type String
#     Write-Output "Hardened UNC Path configured: $valueName -> $valueData"
# }


# $CisNumber = "18.5.19.2.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
# $RegistryName = "DisabledComponents"
# $RegistryValue = 255
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.20.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
# $RegistryChanges = @{
#     "EnableRegistrars" = 0
#     "DisableUPnPRegistrar" = 1
#     "DisableInBand802DOT11Registrar" = 1
#     "DisableFlashConfigRegistrar" = 1
#     "DisableWPDRegistrar" = 1
# }

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     foreach ($RegistryName in $RegistryChanges.Keys) {
#         $RegistryValue = $RegistryChanges[$RegistryName]
#         Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#         Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     }
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.20.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
# $RegistryChanges = @{
#     "EnableRegistrars" = 0
#     "DisableUPnPRegistrar" = 1
#     "DisableInBand802DOT11Registrar" = 1
#     "DisableFlashConfigRegistrar" = 1
#     "DisableWPDRegistrar" = 1
# }

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     foreach ($RegistryName in $RegistryChanges.Keys) {
#         $RegistryValue = $RegistryChanges[$RegistryName]
#         Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#         Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
#     }
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.20.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
# $RegistryName = "DisableWcnUi"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.21.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
# $RegistryName = "fMinimizeConnections"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.5.23.2.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
# $RegistryName = "AutoConnectAllowedOEM"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.6.1"
# $RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
# $RegistryName = "NoWarningNoElevationOnInstall"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.6.3"
# $RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
# $RegistryName = "UpdatePromptSettings"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.7.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
# $RegistryName = "NoCloudApplicationNotification"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
# $RegistryName = "ProcessCreationIncludeCmdLine_Enabled"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
# $RegistryName = "AllowEncryptionOracle"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.4.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
# $RegistryName = "AllowProtectedCreds"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "EnableVirtualizationBasedSecurity"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "RequirePlatformSecurityFeatures"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "HypervisorEnforcedCodeIntegrity"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "HVCIMATRequired"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "LsaCfgFlags"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.5.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# $RegistryName = "ConfigureSystemGuardLaunch"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
# $RegistryName = "1"
# $RegistryValue = "PCI\CC_0C0A"
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.1.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
# $RegistryName = "DenyDeviceIDsRetroactive"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.1.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
# $RegistryName = "DenyDeviceClasses"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.1.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
# $deviceClassGUIDs = @(
#     "{d48179be-ec20-11d1-b6b8-00c04fa372a7}", # IEEE 1394 SBP2 Protocol Class
#     "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}", # IEEE 1394 IEC-61883 Protocol Class
#     "{c06ff265-ae09-48f0-812c-16753d7cba83}", # IEEE 1394 AVC Protocol Class
#     "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"  # IEEE 1394 Host Bus Controller Class
# )

# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     for ($i = 1; $i -le $deviceClassGUIDs.Count; $i++) {
#         Set-RegistryValue -Path $RegistryPath -Name $i -Value $deviceClassGUIDs[$i - 1]
#         Verify-RegistryValue -Path $RegistryPath -Name $i -ExpectedValue $deviceClassGUIDs[$i - 1]
#     }
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.1.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
# $RegistryName = "DenyDeviceClassesRetroactive"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.7.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
# $RegistryName = "PreventDeviceMetadataFromNetwork"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.14.1"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
# $RegistryName = "DriverLoadPolicy"
# $RegistryValue = 3
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.21.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "EnableCdp"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# $RegistryName = "NoUseStoreOpenWith"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
# $RegistryName = "DisableWebPnPDownload"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
# $RegistryName = "PreventHandwritingErrorReports"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
# $RegistryName = "ExitOnMSICW"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.6"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoWebServices"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
# $RegistryName = "DisableHTTPPrinting"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
# $RegistryName = "NoRegistration"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.9"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
# $RegistryName = "DisableContentFileUpdates"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.10"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoOnlinePrintsWizard"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.11"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoPublishingWizard"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.12"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
# $RegistryName = "CEIP"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.13"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
# $RegistryName = "CEIPEnable"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.22.1.14"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
# $RegistryName = "Disabled"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
# $RegistryName = "DoReport"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.25.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
# $RegistryName = "DevicePKInitEnabled"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }
# $RegistryName = "DevicePKInitBehavior"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.26.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
# $RegistryName = "DeviceEnumerationPolicy"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.27.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
# $RegistryName = "BlockUserInputMethodsForSignIn"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.28.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "BlockUserFromShowingAccountDetailsOnSignin"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.28.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "DontDisplayNetworkSelectionUI"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.28.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "DisableLockScreenAppNotifications"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.28.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "AllowDomainPINLogon"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.31.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "AllowCrossDeviceClipboard"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.31.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "UploadUserActivities"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
# $RegistryName = "DCSettingIndex"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
# $RegistryName = "ACSettingIndex"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
# $RegistryName = "DCSettingIndex"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
# $RegistryName = "ACSettingIndex"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
# $RegistryName = "DCSettingIndex"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.34.6.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
# $RegistryName = "ACSettingIndex"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.36.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fAllowUnsolicited"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.36.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fAllowToGetHelp"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.37.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
# $RegistryName = "EnableAuthEpResolution"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.37.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
# $RegistryName = "RestrictRemoteClients"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.48.5.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
# $RegistryName = "DisableQueryRemoteServer"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.48.11.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
# $RegistryName = "ScenarioExecutionEnabled"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.8.50.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
# $RegistryName = "DisabledByGroupPolicy"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
# $RegistryName = "AllowSharedLocalAppData"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.4.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
# $RegistryName = "BlockNonAdminUserInstall"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.5.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
# $RegistryName = "LetAppsActivateWithVoiceAboveLock"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.6.1"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "MSAOptional"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.6.2"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "BlockHostedAppAccessWinRT"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.8.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# $RegistryName = "NoAutoplayfornonVolume"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.8.2"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoAutorun"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.8.3"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoDriveTypeAutoRun"
# $RegistryValue = 255
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.10.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
# $RegistryName = "EnhancedAntiSpoofing"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVDiscoveryVolumeType"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVRecovery"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVManageDRA"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVRecoveryPassword"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVRecoveryKey"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVHideRecoveryPage"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVActiveDirectoryBackup"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVActiveDirectoryInfoToStore"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.9"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVRequireActiveDirectoryBackup"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.10"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVHardwareEncryption"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.11"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVPassphrase"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.12"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVAllowUserCert"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.1.13"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "FDVEnforceUserCert"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "UseEnhancedPin"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSAllowSecureBootForIntegrity"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSRecovery"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSRecovery"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSRecoveryPassword"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSRecoveryKey"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSHideRecoveryPage"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSActiveDirectoryBackup"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.9"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSActiveDirectoryInfoToStore"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.10"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSRequireActiveDirectoryBackup"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.11"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "OSHardwareEncryption"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.2.14"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "EnableBDEWithNoTPM"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVDiscoveryVolumeType"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVRecovery"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVManageDRA"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVRecoveryPassword"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVRecoveryKey"
# $RegistryValue = 2
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVHideRecoveryPage"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVActiveDirectoryBackup"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVActiveDirectoryInfoToStore"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.9"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVRequireActiveDirectoryBackup"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.10"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVHardwareEncryption"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.11"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVPassphrase"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.12"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVAllowUserCert"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.13"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVEnforceUserCert"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.14"
# $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
# $RegistryName = "RDVDenyWriteAccess"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.3.15"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "RDVDenyCrossOrg"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.11.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
# $RegistryName = "DisableExternalDMAUnderLock"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.12.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
# $RegistryName = "AllowCamera"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.14.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableConsumerAccountStateContent"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.14.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableCloudOptimizedContent"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.14.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableWindowsConsumerFeatures"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.15.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
# $RegistryName = "RequirePinForPairing"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.16.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
# $RegistryName = "DisablePasswordReveal"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.16.2"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
# $RegistryName = "EnumerateAdministrators"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.16.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName = "NoLocalPasswordResetQuestions"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "AllowTelemetry"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "DisableEnterpriseAuthProxy"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "DisableOneSettingsDownloads"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "DoNotShowFeedbackNotifications"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "EnableOneSettingsAuditing"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "LimitDiagnosticLogCollection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.7"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
# $RegistryName = "LimitDumpCollection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.17.8"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
# $RegistryName = "AllowBuildPreview"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.18.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
# $RegistryName = "DODownloadMode"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
# $RegistryName = "Retention"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.1.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
# $RegistryName = "MaxSize"
# $RegistryValue = 65536
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.2.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
# $RegistryName = "Retention"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.2.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
# $RegistryName = "MaxSize"
# $RegistryValue = 196608
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
# $RegistryName = "Retention"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
# $RegistryName = "Retention"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.27.4.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
# $RegistryName = "MaxSize"
# $RegistryValue = 65536
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.31.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# $RegistryName = "NoDataExecutionPrevention"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.31.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# $RegistryName = "NoHeapTerminationOnCorruption"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.31.4"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "PreXPSP2ShellProtocolBehavior"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.36.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
# $RegistryName = "DisableHomeGroup"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.41.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
# $RegistryName = "DisableLocation"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.45.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
# $RegistryName = "AllowMessageSync"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.46.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
# $RegistryName = "DisableUserAuth"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.4.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
# $RegistryName = "LocalSettingOverrideSpynetReporting"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.4.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
# $RegistryName = "SpynetReporting"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.5.1.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
# $RegistryName = "ExploitGuard_ASR_Rules"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.5.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
# $RegistryName = "EnableNetworkProtection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.6.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
# $RegistryName = "EnableFileHashComputation"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.9.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
# $RegistryName = "DisableIOAVProtection"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.9.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
# $RegistryName = "DisableRealtimeMonitoring"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.9.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
# $RegistryName = "DisableBehaviorMonitoring"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.9.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
# $RegistryName = "DisableScriptScanning"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.11.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
# $RegistryName = "DisableGenericReports"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.12.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
# $RegistryName = "DisableRemovableDriveScanning"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.12.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
# $RegistryName = "DisableEmailScanning"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.15"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
# $RegistryName = "PUAProtection"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.47.16"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
# $RegistryName = "DisableAntiSpyware"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "AuditApplicationGuard"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "AllowCameraMicrophoneRedirection"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "AllowPersistence"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.4"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "SaveFilesToHost"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.5"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "AppHVSIClipboardSettings"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.48.6"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
# $RegistryName = "AllowAppHVSI_ProviderSet"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.57.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
# $RegistryName = "EnableFeeds"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.58.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
# $RegistryName = "DisableFileSyncNGSC"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.64.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
# $RegistryName = "DisablePushToInstall"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.2.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "DisablePasswordSaving"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.2.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDenyTSConnections"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "EnableUiaRedirection"
# $RegistryValue = 0
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDisableCcm"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.3"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDisableCdm"
# $RegistryValue = 1
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.4 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDisableLocationRedir"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.5 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDisableLPT"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.3.6 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fDisablePNPRedir"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.9.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fPromptForPassword"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.9.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "fEncryptRPCTraffic"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.9.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "SecurityLayer"
# $RegistryValue = 2  # 2 = SSL/TLS
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.9.4 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "UserAuthentication"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.9.5 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "MinEncryptionLevel"
# $RegistryValue = 3  # 3 = High Level
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.10.1 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "MaxIdleTime"
# $RegistryValue = 900000  # 15 minutes in milliseconds (15 * 60 * 1000)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.10.2 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "MaxDisconnectionTime"
# $RegistryValue = 60000  # 1 minute in milliseconds (1 * 60 * 1000)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.65.3.11.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# $RegistryName = "DeleteTempDirsOnExit"
# $RegistryValue = 1  # 1 = Disabled (temporary folders are deleted upon exit)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.66.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
# $RegistryName = "DisableEnclosureDownload"
# $RegistryValue = 1  # 1 = Enabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.67.2 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
# $RegistryName = "AllowCloudSearch"
# $RegistryValue = 0  # 0 = Disable Cloud Search
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.67.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
# $RegistryName = "AllowCortana"
# $RegistryValue = 0  # 0 = Disable Cortana
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.67.4 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
# $RegistryName = "AllowCortanaAboveLock"
# $RegistryValue = 0  # 0 = Disable Cortana above lock screen
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.67.5 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
# $RegistryName = "AllowIndexingEncryptedStoresOrItems"
# $RegistryValue = 0  # 0 = Disable indexing of encrypted files
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.67.6 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
# $RegistryName = "AllowSearchToUseLocation"
# $RegistryValue = 0  # 0 = Disable search and Cortana from using location
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.72.1 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
# $RegistryName = "NoGenTicket"
# $RegistryValue = 1  # 1 = Enable 'Turn off KMS Client Online AVS Validation'
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.75.1 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# $RegistryName = "DisableStoreApps"
# $RegistryValue = 0  # 0 = Disabled (Microsoft Store apps are allowed)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.75.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# $RegistryName = "RequirePrivateStoreOnly"
# $RegistryValue = 1  # 1 = Enabled (Only display the private store within the Microsoft Store)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.75.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# $RegistryName = "AutoDownload"
# $RegistryValue = 2  # 2 = Disabled (automatic download and install of updates is enabled)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.75.4 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# $RegistryName = "DisableOSUpgrade"
# $RegistryValue = 1  # 1 = Enabled (turn off the offer to update to the latest version of Windows)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.75.5 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# $RegistryName = "RemoveWindowsStore"
# $RegistryValue = 1  # 1 = Enabled (turn off the Store application)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.81.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
# $RegistryName = "AllowNewsAndInterests"
# $RegistryValue = 0  # 0 = Disabled (Widgets feature is turned off)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.85.1.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# $RegistryName1 = "EnableSmartScreen"
# $RegistryValue1 = 1  # 1 = Enabled
# $RegistryName2 = "ShellSmartScreenLevel"
# $RegistryValue2 = "Block"  # Block = Warn and prevent bypass
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName1 -Value $RegistryValue1
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName2 -Value $RegistryValue2
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName1 -ExpectedValue $RegistryValue1
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName2 -ExpectedValue $RegistryValue2
# } catch {
#     Write-Host "$CisNumber - Fail" -ForegroundColor Red
# }


# $CisNumber = "18.9.85.2.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
# $RegistryName = "EnabledV9"
# $RegistryValue = 1  # 1 = Enabled (SmartScreen is turned on)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.85.2.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
# $RegistryName = "PreventOverride"
# $RegistryValue = 1  # 1 = Enabled (prevent bypassing SmartScreen prompts)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.87.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
# $RegistryName = "AllowGameDVR"
# $RegistryValue = 0  # 0 = Disabled (Game Recording and Broadcasting is turned off)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.89.1 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
# $RegistryName = "AllowSuggestedAppsInWindowsInkWorkspace"
# $RegistryValue = 0  # 0 = Disabled (suggested apps are not allowed)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.89.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
# $RegistryName = "AllowWindowsInkWorkspace"
# $RegistryValue = 1  # 1 = Enabled: On, but disallow access above lock
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.90.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
# $RegistryName = "EnableUserControl"
# $RegistryValue = 0  # 0 = Disabled (user control over installs is not allowed)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.90.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
# $RegistryName = "AlwaysInstallElevated"
# $RegistryValue = 0  # 0 = Disabled (Windows Installer 
# #                   does not always install with elevated privileges)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.90.3 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
# $RegistryName = "SafeForScripting"
# $RegistryValue = 0  # 0 = Disabled (security prompts are not suppressed)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.91.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# $RegistryName = "DisableAutomaticRestartSignOn"
# $RegistryValue = 1  # 1 = Disabled (automatic sign-in is turned off)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.100.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
# $RegistryName = "EnableScriptBlockLogging"
# $RegistryValue = 1  # 1 = Enabled (PowerShell Script Block Logging is turned on)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.100.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
# $RegistryName = "EnableTranscripting"
# $RegistryValue = 0  # 0 = Disabled (PowerShell Transcription is turned off)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.1.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
# $RegistryName = "AllowBasic"
# $RegistryValue = 0  # 0 = Disabled (Basic authentication is not allowed)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.1.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
# $RegistryName = "AllowUnencryptedTraffic"
# $RegistryValue = 0  # 0 = Disabled (unencrypted traffic blocked)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.1.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
# $RegistryName = "AllowDigest"
# $RegistryValue = 0  # 0 = Disabled (Digest authentication blocked)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.2.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
# $RegistryName = "AllowBasic"
# $RegistryValue = 0  # 0 = Disabled (Basic authentication blocked)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.2.2 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
# $RegistryName = "AllowAutoConfig"
# $RegistryValue = 0  # 0 = Disabled (blocks automatic WinRM listener configuration)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.2.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
# $RegistryName = "AllowUnencryptedTraffic"
# $RegistryValue = 0  # 0 = Disabled (unencrypted traffic blocked)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.102.2.4 (L1)"  # Assuming this is the correct benchmark number
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
# $RegistryName = "DisableRunAs"
# $RegistryValue = 1  # 1 = Enabled (blocks storage of RunAs credentials)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.103.1 (L2)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
# $RegistryName = "AllowRemoteShellAccess"
# $RegistryValue = 0  # 0 = Disabled (blocks Remote Shell access)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.104.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
# $RegistryName = "AllowClipboardRedirection"
# $RegistryValue = 0  # 0 = Disabled (blocks clipboard sharing)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.104.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
# $RegistryName = "AllowNetworking"
# $RegistryValue = 0  # 0 = Disabled (blocks network access)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.105.2.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
# $RegistryName = "DisallowExploitProtectionOverride"
# $RegistryValue = 1  # 1 = Enabled (prevents user modifications)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.1.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
# $RegistryName = "NoAutoRebootWithLoggedOnUsers"
# $RegistryValue = 0  # 0 = Disabled (enables auto-restart functionality)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.2.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
# $RegistryName = "NoAutoUpdate"
# $RegistryValue = 0  # 0 = Enabled (turns ON Automatic Updates)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.2.2 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
# $RegistryName = "ScheduledInstallDay"
# $RegistryValue = 0  # 0 = Every day
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.2.3 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
# $RegistryName = "SetDisablePauseUXAccess"
# $RegistryValue = 1  # 1 = Enabled (blocks pause functionality)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.4.1 (L1)"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
# $RegistryName = "ManagePreviewBuilds"
# $RegistryValue = 1  # 1 = Disabled (blocks preview builds)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.4.2 (L1) - Part 1"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
# $RegistryName = "DeferFeatureUpdates"  # Enables deferral mechanism
# $RegistryValue = 1                     # 1 = Enabled (required for deferral to work)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "18.9.108.4.2 (L1) - Part 2"
# $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
# $RegistryName = "DeferFeatureUpdatesPeriodInDays"  # Sets deferral duration
# $RegistryValue = 180 
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.1.3.1 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
# $RegistryName = "ScreenSaveActive"
# $RegistryValue = "1"  # 1 = Enabled, 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.1.3.2 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
# $RegistryName = "ScreenSaverIsSecure"
# $RegistryValue = "1"  # 1 = Enabled (password required), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.1.3.3 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
# $RegistryName = "ScreenSaveTimeOut"
# $RegistryValue = "300"  # 900 seconds = 15 minutes (CIS max recommended)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.5.1.1 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
# $RegistryName = "NoToastApplicationNotificationOnLockScreen"
# $RegistryValue = 1  # 1 = Enabled (blocks notifications), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.6.6.1.1 (L2)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"
# $RegistryName = "NoImplicitFeedback"
# $RegistryValue = 1  # 1 = Enabled (blocks participation), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.4.1 (L1)"
# $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
# $RegistryName = "SaveZoneInformation"
# $RegistryValue = 2  # 2 = Disabled (preserves zone info), 1 = Enabled (does not preserve)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.4.2 (L1)"
# $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
# $RegistryName = "ScanWithAntiVirus"
# $RegistryValue = 3  # 3 = Enabled (notifies AV), 2 = Prompt user, 1 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.8.1 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "ConfigureWindowsSpotlight"
# $RegistryValue = 2  # 2 = Disabled, 1 = Enabled, 0 = Not configured
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.8.2 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableThirdPartySuggestions"
# $RegistryValue = 1  # 1 = Enabled (blocks third-party suggestions), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.8.3 (L2)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableTailoredExperiencesWithDiagnosticData"
# $RegistryValue = 1  # 1 = Enabled (blocks personalization), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.8.4 (L2)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableWindowsSpotlightFeatures"
# $RegistryValue = 1  # 1 = Enabled (disables all features), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.8.5 (L1)"
# $RegistryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
# $RegistryName = "DisableSpotlightCollectionOnDesktop"
# $RegistryValue = 1  # 1 = Enabled (blocks feature), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.28.1 (L1)"
# $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# $RegistryName = "NoInplaceSharing"
# $RegistryValue = 1  # 1 = Enabled (blocks sharing), 0 = Disabled
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


# $CisNumber = "19.7.43.1 (L1)"
# $RegistryPath = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
# $RegistryName = "AlwaysInstallElevated"
# $RegistryValue = 0  # 0 = Disabled (secure), 1 = Enabled (dangerous)
# try {
#     Ensure-RegistryPath -Path $RegistryPath
#     Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
#     Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
# } catch {
#     Write-Host "$CisNumber - Fail"
# }


$CisNumber = "19.7.47.2.1 (L2)"
$RegistryPath = "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"
$RegistryName = "PreventCodecDownload"
$RegistryValue = 1  # 1 = Enabled (blocks downloads), 0 = Disabled
try {
    Ensure-RegistryPath -Path $RegistryPath
    Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
    Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
} catch {
    Write-Host "$CisNumber - Fail"
}




# Write-Host "Script execution completed. Restart may be required."
# gpupdate
# Read-Host -Prompt "Press Enter to exit"
