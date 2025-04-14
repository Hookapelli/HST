Function fn_VMW-NSX_01506 {
  Write-Host "VMW-NSX_01506" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  $t1s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s" -Method 'GET' -Headers $headers 
  $t1sjson = $t1s | ConvertFrom-Json 

  # Check if status is OK (200)
  if ($t1s.StatusCode -ne 200) {
      Write-Host "Failed to retrieve Tier-1 Gateways"
  }

  if ($t1sjson.result_count -eq 0) {

      Write-Host "No Tier-1 Gateways are deployed. This is Not Applicable."

  } else {

  Write-Host "Tier-1s Found:"$t1sjson.result_count

  }

  foreach ($t1 in $t1sjson.results) {
  
    $t1id = $t1.id
  
    Write-Host "Tier-1:"$t1.display_name"-"$t1id 

    if (!$t1.dhcp_config_paths) {

      Write-Host "No DHCP Configured on"$t1.display_name  

    }

  foreach ($t1dhcppath in $t1.dhcp_config_paths) {

      $t1dhcpconfigpath = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1$t1dhcppath" -Method 'GET' -Headers $headers 
    
      $t1dhcpconfigpathjson = $t1dhcpconfigpath | ConvertFrom-Json 

      Write-Host "   DCHP Config Path Name:"$t1dhcpconfigpathjson.id
      Write-Host "   DCHP Server:"$t1dhcpconfigpathjson.server_address
      Write-Host "   DCHP Config Path:"$t1dhcpconfigpathjson.server_addresses

      # Check if status is OK (200)

      if ($t1s.StatusCode -ne 200) {

          Write-Host "Failed to retrieve Tier-1 Gateways"

      }
    }
  }
}
