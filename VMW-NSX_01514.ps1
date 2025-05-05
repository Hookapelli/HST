Function fn_VMW-NSX_01514 {
  Write-Host "VMW-NSX_01514" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  # Get Tier-1s if they exist

    try { 

    $t1s = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s" -Method 'GET' -Headers $headers  

    } catch {

      Write-Host "No Tier-1 Found"

      Exit

    }
      
    if ($t1s.StatusCode -ne 200) {

      Write-Host "Failed to retrieve Tier-1 Gateways"

      Exit 

    }

    if ($t1s) {

      $t1sjson = $t1s | ConvertFrom-Json

    }

    if ($t1sjson.result_count -eq 0) {

      Write-Host "No T1 Gateways are deployed. This is Not Applicable."

    }

    Write-Host "Tier-1s Found:"$t1sjson.result_count

    foreach ($t1 in $t1sjson.results) {

    Write-Host "Tier-1:"$t1.display_name 

    $t1id = $t1.id

    #Get GW FIrewall Rules

    try {
    
      $gwfws = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s/$t1id/gateway-firewall" -Method 'GET' -Headers $headers 

    } catch {

      Write-Host "No GW Firewall Found"
 
    }
     
    if ($gwfws.StatusCode -ne 200) {

      Write-Host "Failed to retrieve Tier-1 GW Firewall"
    }

    if ($gwfws) {

      $gwfwsjson = $gwfws | ConvertFrom-Json

    }

    if ($gwfwsjson.result_count -eq 0) {

      Write-Host "No Services Found"} else {

      foreach ($gwfwresult in $gwfwsjson.results ) {

        foreach ($gwfwrule in $gwfwresult.rules) {

          $gwfwruleid = $gwfwrule.id

          Write-Host "  $gwfwruleid Logging Enabled:"$gwfwrule.logged 

        }

      } 

    }

  }

}
