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

# Step 8 : ENABLING ASR RULES
# for details go to https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#attack-surface-reduction-rules-by-type
#       Block abuse of exploited vulnerable signed drivers
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Warn
#       Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Warn
#       Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Warn
#       Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Audit
#       Block credential stealing from the Windows local security authority subsystem (lsass.exe)
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
#       Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
#       Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
#       Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Warn
#       Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
#       Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled


# Step 9: DISABLING GEOLOCATION CHECK
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f

New-NetFirewallRule -DisplayName "Block Location Services" -Direction Outbound -Program "%SystemRoot%\System32\lfsvc.dll" -Action Block
New-NetFirewallRule -DisplayName "Block Location Services Inbound" -Direction Inbound -Program "%SystemRoot%\System32\lfsvc.dll" -Action Block

reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f

Stop-Service -Name "SensorService" -Force
Set-Service -Name "SensorService" -StartupType Disabled

Stop-Service -Name "lfsvc" -Force
Set-Service -Name "lfsvc" -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"




# Step {{}}: turning off the smb
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Stop-Service -Name "LanmanServer" -Force
Set-Service -Name "LanmanServer" -StartupType Disabled
Write-Host "Script execution completed successfully." -ForegroundColor Green