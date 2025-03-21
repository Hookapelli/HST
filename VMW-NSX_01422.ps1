Function fn_VMW-NSX_01422 {   # Verify NSX Controller is part of a cluster
  Write-Host "VMW-NSX_01422" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/api-virtual-ip"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.ip_address -eq "0.0.0.0") { Write-Host "No Cluster Configured"} else {
    Write-Host "Cluster Configured on IP: "$response.ip_address
  }
  if ($response.ip6_address -eq "::") { Write-Host "No IPv6 Cluster Configured"} else {
    Write-Host "Cluster Configured on IPv6: "$response.ip6_address
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
