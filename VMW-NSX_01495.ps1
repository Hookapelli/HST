Function fn_VMW-NSX_01495 {
  Write-Host "VMW-NSX_01495" -ForegroundColor Green

# Set the Headder for all API calls
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
$headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

$t0s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s" -Method 'GET' -Headers $headers 
$t0sjson = $t0s | ConvertFrom-Json 

# Check if status is OK (200)
if ($t0s.StatusCode -ne 200) {
    Write-Host "Failed to retrieve Tier-0 Gateways"
}

if ($t0sjson.result_count -eq 0) {
    Write-Host "No T0 Gateways are deployed. This is Not Applicable."
}

Write-Host "Tier-0s Found:"$t0sjson.result_count


# Check shared gateway policies for ICMP rules

$sharedgwpols = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/search?query=resource_type:GatewayPolicy%20AND%20category:sharedPreRules" -Method 'GET' -Headers $headers -SkipCertificateCheck
$sharedgwpolsjson = $sharedgwpols | ConvertFrom-Json

if ($sharedgwpols.StatusCode -ne 200) {
    Write-Host "     Failed to retrieve shared gateway policies"
}

if ($sharedgwpolsjson.result_count -eq "0") {
    Write-Host "     No Shared Gateway Policies Found"
    } else {
        Write-Host "     Shared Gateway Policies Found"}


foreach ($sharedpol in $sharedgwpolsjson.results) {

    $sharedpolicypath = $sharedpol.path

    $sharedrules = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1$sharedpolicypath" -Method 'GET' -Headers $headers -SkipCertificateCheck
    $sharedrulesjson = $sharedrules | ConvertFrom-Json
        
        if ($sharedrules.StatusCode -ne 200) {
            Write-Host "Failed to retrieve shared rules"
            exit
        }
        foreach ($t0 in $t0sjson.results) {
            Write-Host "Tier-0:"$t0.display_name
            foreach ($rule in $sharedrulesjson.rules) {

                if ($t0.path -eq $rule.scope) {
                    if ($rule.services -like "/infra/services/ICMP_Destination_Unreachable") {
                        Write-Host "      ICMP Destination Unreachble Rule found in"$sharedpol.display_name
                    }
                    if ($rule.action -eq 'ALLOW') {
                        Write-Host "     Rule should not allow ICMP mask reply"
                        } else {

                            Write-Host "    ICMP Destination Unreachble Rule"$rule.id"is set to"$rule.action"in"$sharedpol.display_name

                            $sharedICMPRuleFound = "true"
                    }
                }
            }    
        }

    }
}

# If no shared rule found, check specific Tier-0 Gateway rules
if ($sharedICMPRuleFound -ne "true") {
    foreach ($t0 in $t0sjson.results) {
        if ($t0.ha_mode -ne 'ACTIVE_ACTIVE') {
            $gwFwResponse = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$($t0.id)/gateway-firewall" -Method 'GET' -Headers $headers -SkipCertificateCheck
        

            if ($gwFwResponse.StatusCode -ne 200) {
                Write-Host "Failed to retrieve gateway firewall"
            }

            $icmpRuleFound = "false"
            foreach ($res in $gwFwResponse.results) {
                foreach ($rule in $res.rules) {
                    if ($rule.services -notlike "infra/services/ICMP_Redirect") {
                        Write-Host "No ICMP Redirect Service Found"} else {
                            Write-Host "     ICMP Redirect Service Found for:"$t0.display_name
                            if ($rule.action -eq "ALLOW") {
                                Write-Host "     Rule should not be set to ALLOW"
                            } else {
                                Write-Host "     Rule NOT set to ALLOW"
                            }
                        }
                    }
                foreach ($entry in $rule.service_entries) {
                    if ($entry.icmp_type -eq 18) {
                        $icmpRuleFound = "true"
                        if ($rule.action -eq 'ALLOW') {
                            Write-Host "Rule should not allow ICMP mask reply"
                        }
                    }
                }
            }                    
        }
    }

    if ($icmpRuleFound = "false") {
        Write-Host "No firewall rule to block ICMP unreachable traffic found for "$t0.display_name
    } 
}
