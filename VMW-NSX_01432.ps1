Function fn_VMW-NSX_01432 {
  Write-Host "VMW-NSX_01432" -ForegroundColor Green
  # Perform API Call 
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Configured"} else {

    # For each T0R: https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier0-#{t0id}/rules/default_rule
      # action -ne 'ALLOW'
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
