Function fn_VMW-NSX_01437 {
  Write-Host "VMW-NSX_01437" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T1 Deployed"} else {
    foreach ($result in $response.results){
      $t0id = $result.id
      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier0-$t0id/rules/default_rule"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $defaultRule = Invoke-Expression $command2 | ConvertFrom-Json
      Write-Host $result.display_name" Default Rule is: "$defaultRule.action

    }
  }
}
