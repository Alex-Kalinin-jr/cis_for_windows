# Get the WiFi network interface
$wifiInterface = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wi-Fi*"}

# Get the current outgoing rules
$outgoingRules = Get-NetFirewallRule -Direction Outbound

# Create a new rule to block all outgoing traffic
$blockAllRule = New-NetFirewallRule -Name "BlockAllOutbound" -DisplayName "Block All Outbound Traffic" -Direction Outbound -Action Block -Enabled True -InterfaceType Wireless

# Create a new rule to allow HTTPS traffic
$allowHttpsRule = New-NetFirewallRule -Name "AllowHttpsOutbound" -DisplayName "Allow HTTPS Outbound Traffic" -Direction Outbound -Protocol TCP -LocalPort 443 -Action Allow -Enabled True -InterfaceType Wireless

# Add the rules to the firewall
Set-NetFirewallRule -Name $blockAllRule.Name -Enabled True
Set-NetFirewallRule -Name $allowHttpsRule.Name -Enabled True

#Realtek Bluetooth Device Manager Service
#RtkBtManServ
#bthserv
#Служба поддержки Bluetooth
#BluetoothUserService_2a9b1d
#Служба поддержки пользователей Bluetooth_2a9b1d


#RasMan
#Диспетчер подключений удаленного доступа