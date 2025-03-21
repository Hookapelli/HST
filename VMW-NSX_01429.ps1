Function fn_VMW-NSX_01429 {
    Write-Host "VMW-NSX_01429" -ForegroundColor Green
    $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
    $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
    $response = Invoke-Expression $command | ConvertFrom-Json
      if ($response.result_count -eq "0") { Write-Host "No T0 Configured"} else { 
        foreach ($result in $response.results) {
          $t0id=$result.id 
          $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/gateway-firewall"
          $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
          $t0data = Invoke-Expression $command | ConvertFrom-Json
            foreach ($policy in $t0data.results) {
              foreach ($rules in $policy.rules) {
                Write-Host $rules.display_name - $rules.logged
              } 
          }  
        }           
      }
}
