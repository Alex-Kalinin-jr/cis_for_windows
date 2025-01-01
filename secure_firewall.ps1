# Check if the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

#preparation step
Get-NetFirewallRule | Remove-NetFirewallRule

# Step 1: Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Step 2: Block all incoming connections (default deny)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block






# Step 3: Allow all outgoing connections
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Step 4: Enable firewall logging to log dropped packets and successful connections
$LogPath = "E:\logs\firewall.log"
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName $LogPath -LogMaxSizeKilobytes 4096

# Step 5: Allow essential Windows services and traffic for updates, browsing, and downloads
New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 67,68 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow

# Step 6: Add a rule to log and drop all other incoming traffic
New-NetFirewallRule -DisplayName "Block All Other Incoming Traffic" -Direction Inbound -Action Block -Enabled True

# Step 7: Display current firewall configuration
Write-Host "Firewall configuration completed. Current settings:" -ForegroundColor Cyan
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName -AutoSize

Write-Host "Firewall logs will be saved to $LogPath" -ForegroundColor Yellow

#Step 8 : Enabling ASR rules
#       Block abuse of exploited vulnerable signed drivers
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Warn
#       Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Warn
#       Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Warn
#       Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Warn

# Step {{}}: turning off the smb
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Stop-Service -Name "LanmanServer" -Force
Set-Service -Name "LanmanServer" -StartupType Disabled
Write-Host "Script execution completed successfully." -ForegroundColor Green