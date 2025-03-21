Function fn_VMW-NSX_01430 {
  Write-Host "VMW-NSX_01430" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search?query=resource_type:TransportNode%20AND%20node_deployment_info.resource_type:EdgeNode"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No Edge Node Transports Deployed"} else {
    foreach ($result in $response.results){
      $tnid = $result.id 
      Write-Host "Edge Node:" $result.display_name   "ID:"$tnid 
      $uri = "https://$global:NSXmgr/api/v1/transport-nodes/$tnid/node/services/syslog/exporters"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure" 
      $tnsyslog = Invoke-Expression $command2 | ConvertFrom-Json
      if ($tnsyslog.result_count -eq "0") {Write-Host "No Syslog Servers Configured"} else {
        foreach ($logserver in $tnsyslog.results){
          Write-Host "   Level: "$logserver.level
          Write-Host "   Protocol: "$logserver.Protocol
          Write-Host "   Server: "$logserver.server
          Write-Host
        }
      }
    }
  }
}