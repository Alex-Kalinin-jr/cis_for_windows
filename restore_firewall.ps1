# Check if the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "Reverting firewall to default settings..." -ForegroundColor Green

# Step 1: Disable Windows Firewall
Write-Host "Disabling Windows Defender Firewall for all profiles..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Step 2: Reset default inbound and outbound actions to default (Allow for both)
Write-Host "Resetting default inbound and outbound actions to allow..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Step 3: Disable firewall logging
Write-Host "Disabling firewall logging..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked False

# Step 4: Remove all custom rules
Write-Host "Removing all custom firewall rules..." -ForegroundColor Green
Get-NetFirewallRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Step 5: Confirm and display the default settings
Write-Host "Firewall settings restored to default. Current configuration:" -ForegroundColor Cyan
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName -AutoSize

Write-Host "Firewall has been reset to its default configuration." -ForegroundColor Green