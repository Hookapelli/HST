Function fn_VMW-NSX_01504 {
  Write-Host "VMW-NSX_01504" -ForegroundColor Green

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

  foreach ($t0 in $t0sjson.results) {
    
    $t0id = $t0.id
    
    Write-Host "Tier-0:"$t0id 
    
    $t0lss = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services" -Method 'GET' -Headers $headers 
 
    $t0lssjson = $t0lss | ConvertFrom-Json 

    if ($t0lssjson.result_count -eq "null") {

      Write-Host "No Services Found"} else {

        foreach ($t0ls in $t0lssjson.results ) {

          $t0lsid = $t0ls.id

          # Checkin BGP on Each Service

          $bgp = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/bgp" -Method 'GET' -Headers $headers 
          
          $bgpjson = $bgp | ConvertFrom-Json

          # Check if status is OK (200)

          if ($bgp.StatusCode -ne 200) {

            Write-Host "Failed to retrieve BGP Services"

          } else {

            if ($bgpjson.enabled = "true") {

              $bgpnbrs = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/bgp/neighbors" -Method 'GET' -Headers $headers 

              $bgpnbrsjson = $bgpnbrs | ConvertFrom-Json

              # Check if status is OK (200)

              if ($bgpnbrs.StatusCode -ne 200) {

                Write-Host "Failed to retrieve BGP Neighbors"

              } else {

                if ($bgpnbrsjson.result_count -lt "1") {

                  Write-Host "No BGP Neighbors on Tier-0"$t0.display_name 

                } 

              if ($bgpnbrsjson.result_count -gt "0") {

                foreach ($bgpnbrsresult in  $bgpnbrsjson.results) {

                  Write-Host "BGP on"$t0.display_name"neighbor"$bgpnbrsresult.neighbor_address"enabled:"$bgpnbrsresult.enabled

                }

              }

            }

          }

        }

        # Checking OSPF on Each Service

        $ospf = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/ospf" -Method 'GET' -Headers $headers 
          
        $ospfjson = $ospf | ConvertFrom-Json

        # Check if status is OK (200)

        if ($ospf.StatusCode -ne 200) {

          Write-Host "Failed to retrieve OSPF Services"

        } else {if ($ospfjson.enabled -eq "true") {

          $ospfareas = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/ospf/areas" -Method 'GET' -Headers $headers 

          $ospfareasjson = $ospfareas | ConvertFrom-Json

          # Check if status is OK (200)

          if ($ospfareas.StatusCode -ne 200) {

            Write-Host "Failed to retrieve OSPF Services"

          } else {

            if ($ospfareasjson.result_count -gt "0") {

              foreach ($ospfareasresults in $ospfareasjson.results) {

                Write-Host "OSPF on "$t0.display_name"Aria"$ospfareasresults.area_id"enabled"
            
              }
            }
          }
        }
      }
    }
  }
}  
}
