Function fn_VMW-NSX_01414 {   # Verify Logs are being sent to a central log server 
  Write-Host "VMW-NSX_01414" -ForegroundColor Green
  # Is Syslog Running?
  $uri = "https://$global:NSXmgr/api/v1/node/services/syslog/status"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Syslog Service: :"$response.runtime_state

  # Perform API Call to get SysLog Servers
  $uri = "https://$global:NSXmgr/api/v1/node/services/syslog/exporters"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command  | ConvertFrom-Json
  if (!$response.results) { Write-Host "No Syslog Servers Found"} else {
    foreach ($result in $response.results) {
      Write-Output "SysLog Server: $($result.server) - $($result.level)"
    }
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
