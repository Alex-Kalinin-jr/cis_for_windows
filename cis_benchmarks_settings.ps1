if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
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
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
            Write-Host "Registry value '$Name' set to '$Value' at path '$Path'" -ForegroundColor Green
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
        Write-Host "$CisNumber - Success" -ForegroundColor Green
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


$CisNumber = "2.3.10.6"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$RegistryName = "NullSessionPipes"
$RegistryValue = $Null
try {
    Ensure-RegistryPath -Path $RegistryPath
    Set-RegistryValue -Path $RegistryPath -Name $RegistryName -Value $RegistryValue
    Verify-RegistryValue -Path $RegistryPath -Name $RegistryName -ExpectedValue $RegistryValue
} catch {
    Write-Host "$CisNumber - Fail"
}


Write-Host "Script execution completed. Restart may be required."
# Read-Host -Prompt "Press Enter to exit"


