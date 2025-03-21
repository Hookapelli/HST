Function fn_VMW-NSX_01409 {   # Determine if Logging is Enabled for each DFW Policy
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:SecurityPolicy%20AND%20!id:default-layer2-section"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  foreach ($result in $response.results) {
    Write-Host "Policy ID: $($result.id) : $($result.logging_enabled)"
    
  }
}