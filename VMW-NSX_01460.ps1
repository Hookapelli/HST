Function fn_VMW-NSX_01460 {
  Write-Host "VMW-NSX_01460" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  
  if ($response.result_count -eq "0") { Write-Host "No T0 Deployed"} else {
    foreach ($result in $response.results){
      $t0id = $result.id
      Write-Host "Tier-0:"$t0id

      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $response2 = Invoke-Expression $command2 | ConvertFrom-Json 

      if ($response2.result_count -eq "0") {Write-Host "No BGP Services Configured for:"$t0id} else {
          Write-Host "BGP Services Configured for"$t0id

          foreach ($result2 in $response2.results) {
            $lsId = $result2.id
            Write-Host "Local Service ID:"$lsId

            $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$lsID/bgp"
            $command3 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
            $response3 = Invoke-Expression $command3 | ConvertFrom-Json

            if (!$response3.id) {Write-Host "No BGP"} else {
            Write-Host "BGP Configured for:"$t0id

            Write-Host "BGP Enabled:" $response3.Enabled
            Write-Host
          
            $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$lsID/bgp/neighbors"
            $command4 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
            $response4 = Invoke-Expression $command4 | ConvertFrom-Json

            if (!$response4.results) {Write-Host "No BGP Neighbors"} else {
              foreach ($result4 in $response4.results) {
                Write-Host "Neighbor:"$result4.neighbor_address
                if (!$result4.route_filtering) {Write-Host "No Route Filtering Configured"} else {
                  foreach ($rf in $result4.route_filtering) {
                    if (!$rf.maximum_routes) {Write-Host "No Max Routes Configured!"} else {
                      Write-Host "Max Routes Set:"$rf.maximum_routes
                    }
                    Write-Host
                  }
                }
              }
            }    
          }  
        }
      }
    }
  }
}
