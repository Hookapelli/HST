Function fn_VMW-NSX_01503 {
  Write-Host "VMW-NSX_01503" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  $t0s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s" -Method 'GET' -Headers $headers 
  $t0sjson = $t0s | ConvertFrom-Json 

  # Check if status is OK (200)
  if ($t0s.StatusCode -ne 200) {
      Write-Host "Failed to retrieve Tier-0 Gateways"
  }

  if ($t0sjson.result_count -eq 0) {
      Write-Host "No T0 Gateways are deployed. This is Not Applicable."
  }

  Write-Host "Tier-0s Found:"$t0sjson.result_count

  foreach ($t0s in $t0sjson.results) {
      Write-Host "Tier-0:"$t0s.display_name 
      if ($t0.dhcp_config_path -ne "null") {
          Write-Host "DCHP Enabled on"$t0s.display_name

          foreach ($dhcpprofile in $t0s.dhcp_config_paths){
              $dhcpinfo = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1$dhcpprofile" -Method 'GET' -Headers $headers 
              $dhcpinfojson = $dhcpinfo | ConvertFrom-Json 

              Write-Host "   DHCP Profile"$dhcpinfojson.id 
              Write-Host "      DHCP Server Address:" $dhcpinfojson.server_address
              Write-Host "      DHCP Addresses:"$dhcpinfojson.server_addresses
          } 
      } else {
        Write-Host "No DHCP Servers Configured for"$t0s.display_name
    }
  }
}    
