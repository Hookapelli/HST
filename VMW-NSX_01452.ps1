Function fn_VMW-NSX_01452 {
  Write-Host "VMW-NSX_01452" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:DistributedFloodProtectionProfile"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json 
  if ($response.result_count -eq "0") { Write-Host "No Profile Configured"} else {
    foreach ($result in $response.results){ 
        Write-Host "Profile ID:"$result.id 
        Write-Host "RST Enabled:"$result.enable_rst_spoofing
        Write-Host "SYN Cache:"$result.enable_syncache    
        Write-Host
        }
            
    }
}
