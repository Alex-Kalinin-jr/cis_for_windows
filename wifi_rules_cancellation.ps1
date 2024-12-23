# Get the rules to remove
$blockAllRule = Get-NetFirewallRule -Name "BlockAllOutbound"
$allowHttpsRule = Get-NetFirewallRule -Name "AllowHttpsOutbound"

# Remove the rules
Remove-NetFirewallRule -Name $blockAllRule.Name -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name $allowHttpsRule.Name -ErrorAction SilentlyContinue