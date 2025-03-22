Function fn_VMW-NSX_01437 {
  Write-Host "VMW-NSX_01437" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Deployed"} else {
    foreach ($result in $response.results){
      $t0id = $result.id
      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $services = Invoke-Expression $command2 #| ConvertFrom-Json
      Write-Host $result.display_name
      $services
    }
  }
}
