Function fn_VMW-NSX_01423 {
  Write-Host "VMW-NSX_01423" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/api-service"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "API Rate Limit:" $response.client_api_rate_limit
  Write-Host "API Concurrency Limit:" $response.global_api_concurrency_limit
  Write-Host "Global API Limit:" $response.client_api_concurrency_limit
  Write-Host "-------------------------------------------------------"
  Write-Host
}
