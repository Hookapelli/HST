Function fn_VMW-NSX_01412 {   # Determine if Defauly Layer 3 Rule is configured to DROP
  Write-Host "VMW-NSX_01412" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  Write-Host "Defauly Layer 3 Rule: "$response.action
  Write-Host "-------------------------------------------------------"
  Write-Host
}
