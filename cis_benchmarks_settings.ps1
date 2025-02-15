if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

#2.3.1.2
# Ensure the script runs with Administrator privileges
$ErrorActionPreference = "Stop"

# Define the registry path and key
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegName = "NoConnectedUser"
$RegValue = 3  # Users can't add or log on with Microsoft accounts

# Check if the registry key exists
if (!(Test-Path $RegPath)) {
    Write-Host "Creating registry path: $RegPath"
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the registry value
Write-Host "Setting $RegName to $RegValue in $RegPath"
Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord

# Confirm the setting was applied
$AppliedValue = (Get-ItemProperty -Path $RegPath -Name $RegName).$RegName
if ($AppliedValue -eq $RegValue) {
    Write-Host "Successfully set 'Accounts: Block Microsoft accounts' to the recommended value ($RegValue)."
} else {
    Write-Host "Failed to apply the setting. Please check manually."
}

# Force policy update (not needed on Home edition, but safe to run)
Write-Host "Applying changes..."
Stop-Process -Name explorer -Force
Start-Process explorer



# 2.3.1.3
# Disable the Guest account
$GuestAccount = "Dguest"
Write-Host "Disabling the Guest account..." -ForegroundColor Yellow
Try {
    Get-LocalUser -Name $GuestAccount | Disable-LocalUser
    Write-Host "Guest account has been successfully disabled." -ForegroundColor Green
} Catch {
    Write-Host "Error: Unable to disable the Guest account. Ensure the script is running as Administrator." -ForegroundColor Red
}


# 2.3.1.4
# Enable the policy: Limit blank password use to console logon only
Write-Host "Enforcing 'Limit local account use of blank passwords to console logon only' policy..." -ForegroundColor Yellow
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
    Write-Host "Policy successfully enforced." -ForegroundColor Green
} Catch {
    Write-Host "Error: Unable to enforce the policy. Ensure the script is running as Administrator." -ForegroundColor Red
}


# 2.3.1.5
# Run this script as an Administrator
# Rename the built-in Administrator account

# Define the new name for the Administrator account
$NewAdminName = "Dadmin"  # Change this to your preferred name
$NewDescription = "System Management Account of my testing pc"
$AdminAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "*-500" }

if ($AdminAccount) {
    # Rename the Administrator account
    Rename-LocalUser -Name $AdminAccount.Name -NewName $NewAdminName
    Write-Output "Administrator account renamed to: $NewAdminName"

    # Update the account description
    Get-LocalUser -Name $NewAdminName | Set-LocalUser -Description $NewDescription
    Write-Output "Administrator account description updated."

    # Confirm the changes
    Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object Name, Description
} else {
    Write-Output "The built-in Administrator account was not found or is disabled."
}

# 2.3.1.6
# Define the new name for the Guest account
$NewGuestName = "Dguest"  # Change this to your preferred name
$NewDescription = "Limited access guest account for my notebook"

$GuestAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "*-501" }

if ($GuestAccount) {
    # Rename the Guest account
    Rename-LocalUser -Name $GuestAccount.Name -NewName $NewGuestName
    Write-Output "Guest account renamed to: $NewGuestName"

    # Update the account description
    Get-LocalUser -Name $NewGuestName | Set-LocalUser -Description $NewDescription
    Write-Output "Guest account description updated."

    # Confirm the changes
    Get-LocalUser | Where-Object { $_.SID -like "*-501" } | Select-Object Name, Description
} else {
    Write-Output "The built-in Guest account was not found or is disabled."
}


#2.3.2.1
# Define the registry path and value
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RegistryName = "SCENoApplyLegacyAuditPolicy"
$RegistryValue = 1
$CISNumber = "2.3.2.1"

# Check if the registry key exists
if (-not (Test-Path $RegistryPath)) {
    Write-Host "Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value to enable the policy
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Force
    Write-Host "$CISNumber - successful" -ForegroundColor Green
} catch {
    Write-Host "$CISNumber - Failed to set the registry value. Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Host "$CISNumber - successful" -ForegroundColor Green

} else {
    Write-Host "$CISNumber - Failed" -ForegroundColor Red

}


# 2.3.2.2
$RegistryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$RegistryName = "CrashOnAuditFail"
$RegistryValue = 0
$CISNumber = "2.3.2.2"

# Check if the registry key exists
if (-not (Test-Path $RegistryPath)) {
    Write-Host "$CISNumber - Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value to enable the policy
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Force
} catch {
    Write-Host "$CISNumber - Failed to set the registry value. Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Host "$CISNumber - successful" -ForegroundColor Green

} else {
    Write-Host "$CISNumber - Failed" -ForegroundColor Red

}


# 2.3.4.1
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
$RegistryName = "AddPrinterDrivers"
$RegistryValue = 0
$CISNumber = "2.3.4.1"

# Check if the registry key exists
if (-not (Test-Path $RegistryPath)) {
    Write-Host "$CISNumber - Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value to enable the policy
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Force
} catch {
    Write-Host "$CISNumber - Failed to set the registry value. Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Host "$CISNumber - successful" -ForegroundColor Green

} else {
    Write-Host "$CISNumber - Failed" -ForegroundColor Red

}


# 2.3.7.1
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegistryName = "DisableCAD"
$RegistryValue = 0
$CISNumber = "2.3.7.1"

# Check if the registry key exists
if (-not (Test-Path $RegistryPath)) {
    Write-Host "$CISNumber - Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value to enable the policy
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Force
} catch {
    Write-Host "$CISNumber - Failed to set the registry value. Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Host "$CISNumber - successful" -ForegroundColor Green

} else {
    Write-Host "$CISNumber - Failed" -ForegroundColor Red

}


# 2.3.7.2
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegistryName = "DontDisplayLastUserName"
$RegistryValue = 1
$CISNumber = "2.3.7.2"

# Check if the registry key exists
if (-not (Test-Path $RegistryPath)) {
    Write-Host "$CISNumber - Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value to enable the policy
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Force
    Write-Host "$CISNumber - successful" -ForegroundColor Green
} catch {
    Write-Host "$CISNumber - Failed to set the registry value. Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Host "$CISNumber - successful" -ForegroundColor Green

} else {
    Write-Host "$CISNumber - Failed" -ForegroundColor Red

}


#2.3.7.4
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegistryName = "InactivityTimeoutSecs"
$DesiredValue = 600  # Replace with a value of 900 or fewer seconds, but not 0
$CISNumber = "2.3.7.2"

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the registry value
try {
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $DesiredValue -Force
} catch {
    Write-Host "Failed to set the registry value. Error: $_" -ForegroundColor Red
}


# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName | Select-Object -ExpandProperty $RegistryName
if ($CurrentValue -eq $DesiredValue) {
    Write-Host "$CISNumber - successful"
} else {
    Write-Host "$CISNumber - failed" -ForegroundColor Red
}


# 2.3.7.5
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$MessageTextKey = "LegalNoticeText"
$MessageTextValue = "Are you sure you want to get access to this supermachine, bitch?"
$CISNumber = "2.3.7.5"

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Registry path does not exist: $RegistryPath. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

try {
    Set-ItemProperty -Path $RegistryPath -Name $MessageTextKey -Value $MessageTextValue -Force
} catch {
    Write-Host "$CISNumber - Error: $_" -ForegroundColor Red
}

# Confirm the change
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $MessageTextKey | Select-Object -ExpandProperty $MessageTextKey
if ($CurrentValue -eq $MessageTextValue) {
    Write-Host "$CISNumber - successful"
} else {
    Write-Host "$CISNumber - failed" -ForegroundColor Red
}




Write-Host "✅ Script execution completed. Restart may be required."