Function fn_VMW-NSX_01502 {
  $uri = "https://$global:NSXmgr/api/v1/node/services/snmp"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  Write-Host "SNMP v2: "$response.service_properties.v2_configured
}
