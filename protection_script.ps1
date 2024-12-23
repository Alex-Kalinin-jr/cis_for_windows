if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Step 1: Enable Windows Firewall
Write-Host "Enabling Windows Defender Firewall..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Step 2: Block all incoming connections (default deny)
Write-Host "Blocking all incoming connections (default deny)..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Step 3: Allow all outgoing connections
Write-Host "Allowing all outgoing connections..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Step 4: Enable firewall logging to log dropped packets and successful connections
Write-Host "Enabling firewall logging for dropped packets and successful connections..." -ForegroundColor Green
# Set log file path and size
$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName $LogPath -LogMaxSizeKilobytes 4096

# Step 5: Add rules to allow essential Windows services (optional)
Write-Host "Allowing essential Windows services (DHCP, DNS, etc.)..." -ForegroundColor Green
# Allow DHCP (UDP ports 67 and 68)
New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 67,68 -Action Allow
# Allow DNS (UDP port 53)
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
# Allow ICMP (ping) requests
New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -Action Allow

# Step 6: Add a rule to log and drop all other incoming traffic
Write-Host "Blocking and logging all other incoming traffic..." -ForegroundColor Green
New-NetFirewallRule -DisplayName "Block All Other Incoming Traffic" -Direction Inbound -Action Block -Enabled True

# Step 7: Display current firewall configuration
Write-Host "Firewall configuration completed. Current settings:" -ForegroundColor Cyan
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName -AutoSize

Write-Host "Firewall logs will be saved to $LogPath" -ForegroundColor Yellow
Write-Host "Script execution completed successfully." -ForegroundColor Green