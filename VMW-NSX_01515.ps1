Function fn_VMW-NSX_01515 {
  Write-Host "VMW-NSX_01515" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-1s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  
  if ($response.result_count -eq "0") { Write-Host "No T1 Deployed"} else {
    foreach ($result in $response.results){
      $t1id = $result.id
      Write-Host "Tier-1:"$t1id
      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-1s/$t1id/flood-protection-profile-bindings/default"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $t1fpp = Invoke-Expression $command2 | ConvertFrom-Json 

      if ($t1fpp.httpStatus -eq "NOT_FOUND") {Write-Host "No Gateway Flood Protection Profiles Binding Found for"$t1id} else {
          Write-Host "Gateway Flood Protection Profile Binding found for"$t1id

        $uri =  "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:GatewayFloodProtectionProfile"
        $command3 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
        $t1gfpp = Invoke-Expression $command3 | ConvertFrom-Json

        if ($t1gfpp.httpStatus -eq "NOT_FOUND") {Write-Host "No Distributed Flood Protection Profiles Found"} else {
        Write-Host "Distrubuted Flood Protection Profile found for"$t1id

        if (!$t1gfpp.results) {Write-Host "No Gateway Flood Protection Profiles Found"} else {
          foreach ($result3 in $t1gfpp.results) {
            $gfppid = $result3.id
            
            $uri =  "https://$global:NSXmgr/policy/api/v1/infra/flood-protection-profiles/$gfppid"
            $command4 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
            $result4 = Invoke-Expression $command4 | ConvertFrom-Json

            Write-Host "Flood Protection Profile:"$gfppid

            Write-Host "udp_active_flow_limit: " -NoNewline
            if (!$result4.udp_active_flow_limit) {Write-Host "Not Set"} else {Write-Host "Set"}

            Write-Host "icmp_active_flow_limit: " -NoNewline
            if (!$result4.icmp_active_flow_limit) {Write-Host "Not Set"} else {Write-Host "Set"}

            Write-Host "tcp_half_open_conn_limit: " -NoNewline
            if (!$result4.tcp_half_open_conn_limit) {Write-Host "Not Set"} else {Write-Host "Set"}

            Write-Host "udp_other_active_conn_limit: " -NoNewline
            if (!$result4.other_active_conn_limit) {Write-Host "Not Set"} else {Write-Host "Set"}

            Write-Host
            }        
          }  
        }
      }
    }
  }
}
