Function fn_VMW-NSX_01469 {
  Write-Host "VMW-NSX_01469" -ForegroundColor Green
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

      if ($response2.result_count -eq "0") {Write-Host "No Services Configured for:"$t0id} else {
          Write-Host "Services Configured for"$t0id

          foreach ($result2 in $response2.results) {
            $lsId = $result2.id
            Write-Host "Local Service ID:"$lsId

            $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$lsID/interfaces"
            $command3 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
            $response3 = Invoke-Expression $command3 | ConvertFrom-Json

            Write-Host "Interfaces for:"$t0id

            if ($response3.result_count -lt 1) {Write-Host "No Interfaces"} else {
            

            foreach ($result3 in $response3.results) {
            Write-Host "   Interface:" $result3.unique_id
            Write-Host "   URPF Mode:" $result3.urpf_mode
            Write-Host
            }
          }  
        }
      }
    }
  }
}
