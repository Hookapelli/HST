Function fn_VMW-NSX_01421 {   # Aslo Supports VMW-NSX_01525, VMW-NSX_01526, VMW-NSX_01527, VMW-NSX_01528, VMW-NSX_01530  
  Write-Host "VMW-NSX_014 & Others" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/node/aaa/auth-policy"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json -Depth 10
  Write-Host "VMW-NSX_01421 - Minimum Password Length:" $response.minimum_password_length
  Write-Host "VMW-NSX_01525 - Enforce Uppercase:" $response.upper_chars 
  Write-Host "VMW-NSX_01526 - Enforce Lowercase:" $response.lower_chars
  Write-Host "VMW-NSX_01527 - Enforce Numeric Character:" $response.digits
  Write-Host "VMW-NSX_01528 - Enforce Special Characters:" $response.special_chars
  Write-Host "VMW-NSX_01530 - Enforce  Unique Password Change:" $response.max_repeats
  Write-Host "-------------------------------------------------------"
  Write-Host
}
