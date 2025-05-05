Function fn_VMW-NSX_01531 {
  Write-Host "VMW-NSX_01531" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  # Get Tier-0s if they exist

  try { 

    $t0s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s" -Method 'GET' -Headers $headers  

    } catch {

      Write-Host "No Tier-0 Found"

      Exit

    }
      
    if ($t0s.StatusCode -ne 200) {

      Write-Host "Failed to retrieve Tier-0 Gateways"

      Exit 

    }

    if ($t0s) {

      $t0sjson = $t0s | ConvertFrom-Json

    }

    if ($t0sjson.result_count -eq 0) {

      Write-Host "No T0 Gateways are deployed. This is Not Applicable."

    }

    Write-Host "Tier-0s Found:"$t0sjson.result_count

    foreach ($t0 in $t0sjson.results) {

    Write-Host "Tier-0:"$t0.display_name 

      $t0ndprofile = $t0.ipv6_profile_paths | Where-Object {$_ -like '*ipv6-ndra-profiles*'} | Select-Object -First 1

      try {

      $ndprofile = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1$t0ndprofile" -Method 'GET' -Headers $headers
      
      } catch {

      Write-Host "Could Not Retrieve IPv6 Forwarding Information"
      
      Exit

      }

      if ($ndprofile) {

        $ndprofilejson = $ndprofile | ConvertFrom-Json

        Write-Host "  IPv6 Profile Hop Limit:"$ndprofilejson.ra_config.hop_limit # Should be Greater than or Equal to 32

      } else {

        Write-Host "  IPv6 Forwarding Not Enabled"

      }
      
  }  

}   
