Function fn_VMW-NSX_01505 {
  Write-Host "VMW-NSX_01505" -ForegroundColor Green

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

          $t0mc = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/multicast" -Method 'GET' -Headers $headers 
 
          $t0mcjson = $t0mc | ConvertFrom-Json 

          # Check if status is OK (200)

          if ($t0mc.StatusCode -ne 200) {

            Write-Host "Failed to retrieve Multicast Information"
          } 

          # Check if status is Not Found (404)

          if ($t0mc.StatusCode -eq 404) {

            Write-Host "Multicast has not been enabled."

          } else {
              
            if ($t0mcjson.enabled -ne "true") {

              $t0int = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/interfaces" -Method 'GET' -Headers $headers 
 
              $t0intjson = $t0int | ConvertFrom-Json
 
              # Check if status is OK (200)

              Write-Host $t0int.StatusCode -ForegroundColor Red

              if ($t0int.StatusCode -ne 200) {

                Write-Host "Failed to retrieve Interface Information"

              } 

              Write-Host "Multicast for"$t0.display_name"is not enabled so all interfaces should have multicast disabled"

              foreach ($int in $t0intjson.results){

                if ($int.multicast.enabled -ne "true") {$intmc="Disabled"} else {

                  $intmc = $int.multicast.enabled

                }

                Write-Host "Tier-0"$t0.display_name"Interface:"$int.id "Multicast Enabled:"$intmc

            }

          }
       
        }

        if ($t0mcjson.enabled -eq "true") {

          Write-Host "Multicast Enabled on"$t0.display_name

      }
    }  
  }   
}    
}   
