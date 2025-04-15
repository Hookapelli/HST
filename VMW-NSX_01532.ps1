Function fn_VMW-NSX_01532 {
  Write-Host "VMW-NSX_01532" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")


  # Check if status is OK (200)
  try { 

    $t1s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s" -Method 'GET' -Headers $headers  
  
    } catch {

      Write-Host "No Tier-1 Found"

    }
      if ($t1s.StatusCode -ne 200) {

      Write-Host "Failed to retrieve Tier-1 Gateways"
  }

  if ($t1s) {

    $t1sjson = $t1s | ConvertFrom-Json

  }

  if ($t1sjson.result_count -eq 0) {

    Write-Host "No T1 Gateways are deployed. This is Not Applicable."

  }


  Write-Host "Tier-1s Found:"$t1sjson.result_count

  foreach ($t1s in $t1sjson.results) {

      Write-Host "Tier-1:"$t1s.display_name 

      if ($t1.dhcp_config_path) {
      
        Write-Host "DCHP Enabled on"$t1s.display_name

          foreach ($dhcpprofile in $t1s.dhcp_config_paths){
      
            $dhcpinfo = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1$dhcpprofile" -Method 'GET' -Headers $headers 
      
            $dhcpinfojson = $dhcpinfo | ConvertFrom-Json 

              Write-Host "   DHCP Profile"$dhcpinfojson.id 
      
              Write-Host "      DHCP Server Address:" $dhcpinfojson.server_address
      
              Write-Host "      DHCP Addresses:"$dhcpinfojson.server_addresses # Shoild Match Input File Data
          } 
      
        } else {
      
          Write-Host "No DHCP Servers Configured for"$t1s.display_name
    

        }

      }

    }  
