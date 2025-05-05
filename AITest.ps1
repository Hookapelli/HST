# Make the initial request to get Tier-0 Gateways
$t0sResponse = Invoke-RestMethod -Uri "$nsxManager/global-manager/policy/api/v1/infra/tier-0s" `
    -Headers @{ 
        'Accept' = 'application/json'
        'X-XSRF-TOKEN' = $sessionToken
        'Cookie' = $sessionCookieId
    } `
    -Method Get

# Check if status is OK (200)
if ($t0sResponse.StatusCode -ne 200) {
    Write-Host "Failed to retrieve Tier-0 Gateways"
    return
}

if ($t0sResponse.results.Count -eq 0) {
    Write-Host "No T0 Gateways are deployed. This is Not Applicable."
    return
}

# Check if there are any custom ICMP mask reply services
$icmpServiceResponse = Invoke-RestMethod -Uri "$nsxManager/policy/api/v1/search?query=(resource_type:Service%20AND%20service_entries.icmp_type:18)" `
    -Headers @{ 
        'Accept' = 'application/json'
        'X-XSRF-TOKEN' = $sessionToken
        'Cookie' = $sessionCookieId
    } `
    -Method Get

if ($icmpServiceResponse.StatusCode -ne 200) {
    Write-Host "Failed to retrieve ICMP service"
    return
}

$icmpServicePath = if ($icmpServiceResponse.result_count -eq 1) {
    $icmpServiceResponse.results[0].path
} else {
    '/did/not/find/anything'
}

# Check shared gateway policies for ICMP rules
$sharedGwPolResponse = Invoke-RestMethod -Uri "$nsxManager/policy/api/v1/search?query=(resource_type:GatewayPolicy%20AND%20category:SharedPreRules)" `
    -Headers @{ 
        'Accept' = 'application/json'
        'X-XSRF-TOKEN' = $sessionToken
        'Cookie' = $sessionCookieId
    } `
    -Method Get

if ($sharedGwPolResponse.StatusCode -ne 200) {
    Write-Host "Failed to retrieve shared gateway policies"
    return
}

$sharedICMPRuleFound = $false
foreach ($sharedPolicy in $sharedGwPolResponse.results) {
    $sharedPolicyPath = $sharedPolicy.path
    $sharedRulesResponse = Invoke-RestMethod -Uri "$nsxManager/policy/api/v1$sharedPolicyPath" `
        -Headers @{ 
            'Accept' = 'application/json'
            'X-XSRF-TOKEN' = $sessionToken
            'Cookie' = $sessionCookieId
        } `
        -Method Get

    if ($sharedRulesResponse.StatusCode -ne 200) {
        Write-Host "Failed to retrieve shared rules"
        continue
    }

    foreach ($rule in $sharedRulesResponse.rules) {
        if ($rule.service_entries -ne $null) {
            foreach ($entry in $rule.service_entries) {
                if ($entry.icmp_type -eq 18) {
                    $sharedICMPRuleFound = $true
                    if ($rule.action -eq 'ALLOW') {
                        Write-Host "Rule should not allow ICMP mask reply"
                    }
                }
            }
        } elseif ($rule.services -contains $icmpServicePath) {
            $sharedICMPRuleFound = $true
            if ($rule.action -eq 'ALLOW') {
                Write-Host "Rule should not allow ICMP mask reply"
            }
        }
    }
}

# If no shared rule found, check specific Tier-0 Gateway rules
if (-not $sharedICMPRuleFound) {
    foreach ($t0 in $t0sResponse.results) {
        if ($t0.ha_mode -ne 'ACTIVE_ACTIVE') {
            $gwFwResponse = Invoke-RestMethod -Uri "$nsxManager/policy/api/v1/infra/tier-0s/$($t0.id)/gateway-firewall" `
                -Headers @{ 
                    'Accept' = 'application/json'
                    'X-XSRF-TOKEN' = $sessionToken
                    'Cookie' = $sessionCookieId
                } `
                -Method Get

            if ($gwFwResponse.StatusCode -ne 200) {
                Write-Host "Failed to retrieve gateway firewall"
                continue
            }

            $icmpRuleFound = $false
            foreach ($res in $gwFwResponse.results) {
                foreach ($rule in $res.rules) {
                    if ($rule.service_entries -ne $null) {
                        foreach ($entry in $rule.service_entries) {
                            if ($entry.icmp_type -eq 18) {
                                $icmpRuleFound = $true
                                if ($rule.action -eq 'ALLOW') {
                                    Write-Host "Rule should not allow ICMP mask reply"
                                }
                            }
                        }
                    } elseif ($rule.services -contains $icmpServicePath) {
                        $icmpRuleFound = $true
                        if ($rule.action -eq 'ALLOW') {
                            Write-Host "Rule should not allow ICMP mask reply"
                        }
                    }
                }
            }

            if (-not $icmpRuleFound) {
                Write-Host "No firewall rule to block ICMP unreachable traffic found"
            }
        }
    }
}
