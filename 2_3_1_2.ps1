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
    Write-Host "✅ Successfully set 'Accounts: Block Microsoft accounts' to the recommended value ($RegValue)."
} else {
    Write-Host "❌ Failed to apply the setting. Please check manually."
}

# Force policy update (not needed on Home edition, but safe to run)
Write-Host "Applying changes..."
Stop-Process -Name explorer -Force
Start-Process explorer

Write-Host "✅ Script execution completed. Restart may be required."