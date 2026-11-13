# Apply or remove an explicit remote address block on this Windows host.
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [ValidateSet('Block', 'Unblock')] [string] $Action,
    [Parameter(Mandatory)] [string] $Address
)
$ErrorActionPreference = 'Stop'
$ip = $null
if ($Address -notmatch '^[0-9a-fA-F:.]+$' -or
    -not [System.Net.IPAddress]::TryParse($Address, [ref] $ip) -or
    $Address -ne $ip.ToString() -or
    [System.Net.IPAddress]::IsLoopback($ip) -or
    $ip.IsIPv4MappedToIPv6 -or $ip.IsIPv6Multicast -or
    $Address -in @('0.0.0.0', '::', '255.255.255.255')) {
    throw 'Enter one canonical remote IP address.'
}
$store = 'PersistentStore'
$group = 'IntegrityGuard Manual'
$rules = @{}
$existingRules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop)
foreach ($direction in @('Inbound', 'Outbound')) {
    $name = "IntegrityGuard.Manual.$direction.$Address"
    $matches = @($existingRules | Where-Object Name -eq $name)
    if ($matches.Count -gt 1) {
        throw "Multiple firewall rules match the operation: $name"
    }
    $existing = $matches | Select-Object -First 1
    if ($existing -and $existing.Group -ne $group) {
        throw "Firewall rule name is already used outside the IntegrityGuard group: $name"
    }
    if ($existing -and $Action -eq 'Block') {
        $remote = @($existing | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)
        if ($existing.Enabled -ne 'True' -or $existing.Action -ne 'Block' -or
            $existing.Direction -ne $direction -or $existing.Profile -ne 'Any' -or
            $remote.Count -ne 1 -or $remote[0] -ne $Address) {
            throw "Existing IntegrityGuard rule does not match the requested block: $name"
        }
    }
    $rules[$direction] = $existing
}
foreach ($direction in @('Inbound', 'Outbound')) {
    $name = "IntegrityGuard.Manual.$direction.$Address"
    if (-not $PSCmdlet.ShouldProcess($Address, "$Action $direction traffic")) { continue }
    $existing = $rules[$direction]
    if ($Action -eq 'Block') {
        if (-not $existing) {
            New-NetFirewallRule -PolicyStore $store -Name $name -DisplayName $name `
                -Group $group -Direction $direction -Action Block `
                -RemoteAddress $Address -Profile Any -Enabled True
        }
    } elseif ($existing) {
        $existing | Remove-NetFirewallRule
    }
}
