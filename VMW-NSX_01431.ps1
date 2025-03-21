Function fn_VMW-NSX_01431 {
  Write-Host "VMW-NSX_01431"  -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-1s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T1 Deployed"} else {

    # For each T1R: 
      # https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier1-#{t1id}/rules/default_rule
        # action -ne 'ALLOW'
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
