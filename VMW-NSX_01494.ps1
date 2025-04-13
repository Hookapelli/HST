Function fn_VMW-NSX_01494 {
  Write-Host "VMW-NSX_01494" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Deployed"} else {
    foreach ($result in $response.results){
      $t0id = $result.id
      $t0HA = $result.ha_mode
      Write-Host "Tier-0:"$t0id
      Write-Host "HA Mode:"$t0HA
      $uri =  "https://$global:NSXmgr/policy/api/v1/search?query=resource_type:GatewayPolicy%20AND%20category:SharedPreRules"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $response2 = Invoke-Expression $command2 | ConvertFrom-Json 
      Write-Host "Checking Shared Rules-" -ForegroundColor Yello
      if ($response2.result_count -lt "1") {Write-Host "No Shared Rules for"$t0id -ForegroundColor Red} else {
          Write-Host "Shared Rules for: "$t0id
          foreach ($result2 in $response2.results) {
            $sharepol = $result2.path
            $uri =  "https://$global:NSXmgr/policy/api/v1$sharepol"
            $command3 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
            $response3 = Invoke-Expression $command3 | ConvertFrom-Json
            
            if (!$response3.rules) {Write-Host "No Shared Rules for"$t0id -ForegroundColor Red} else {
                foreach ($rules in $response3.rules) {
                    if ($rules.services -like "/infra/services/ICMP_Destination_Unreachable") {               
                        Write-Host "Shared ICMP Destination Unreachable Found"
                        $RuleFound = "1"        
                        if ($rules.action -eq "ALLOW") {write-Host "ICMP Destination Unreachable set to ALLOW" -ForegroundColor Red} else {
                            Write-Host "ICMP_Destination_Unreachable not ALLOW"      
                        }
                    } 
                } 
                Write-Host
            }
    # If shared rule not found check gateway specific rules
            Write-Host "Checking Gateway Firewall Rules" -ForegroundColor Yellow
            if ($RuleFound -ne "1") {
                if ($t0HA -eq "ACTIVE_ACTIVE") {
                    $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/gateway-firewall"
                    $command4 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"              
                    $response4 = Invoke-Expression $command4 | ConvertFrom-Json
                    if ($response4.result_count -lt 1) { Write-Host "No Gateway Firewall Rules Found"} else {       
                        foreach ($result4 in $response4.results) {
                            $rules = $result4.rules
                            foreach ($services in $rules.services) {
                                if ($services -like "/infra/services/ICMP_Destination_Unreachable") {
                                    Write-Host "Gateway ICMP Destination Unreachable Found in"$rules.resource_type"-"$rules.id
                                    $RuleFound = "1"  
                                        if ($rules.action -eq "ALLOW") {write-Host "ICMP Destination Unreachable set to ALLOW" -ForegroundColor Red} else {
                                            Write-Host "ICMP_Destination_Unreachable not ALLOW"                   
                                        }
                                    }
                                    
                                } 
                            }
                        }
                    }
                    if ($RuleFound -eq "1") { Write-Host "ICMP Rule Found" } else {
                        Write-Host "ICMP Rule NOT found!" -ForegroundColor Red
                        }
                    }
                }  
            }
        }
   }
}
