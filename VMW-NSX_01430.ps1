Function fn_VMW-NSX_01430 {
  Write-Host "VMW-NSX_01430" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:TransportNode%20AND%20node_deployment_info.resource_type:EdgeNode"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No Edge Node Transports Deployed"} else {
    <# 
      # Get the tnid for each Transport Node

        # For EACG EdgeNode: https://$global:NSXmgr/api/v1/transport-nodes/#{tnid}/node/services/syslog/exporters

          # For EACH 'tnid':
            # level -eq  'INFO'
            # protocol -like ['TCP', 'TLS', 'LI-TLS'
            # server -eq input('syslogServers')}" }
    #> 
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
