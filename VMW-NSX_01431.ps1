Function fn_VMW-NSX_01431 {
  Write-Host "VMW-NSX_01431"  -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-1s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T1 Deployed"} else {
    foreach ($result in $response.results){
      $t1id = $result.id
      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier1-$t1id/rules/default_rule"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $defaultRule = Invoke-Expression $command2 | ConvertFrom-Json
      Write-Host $result.display_name" Default Rule is: "$defaultRule.action

    }
  }
}