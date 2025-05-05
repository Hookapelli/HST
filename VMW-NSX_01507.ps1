Function fn_VMW-NSX_01507 {
  Write-Host "VMW-NSX_01507" -ForegroundColor Green

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
      Write-Host "No T1 Gateways are deployed. This is Not Applicable."
  }

  Write-Host "Tier-1s Found:"$t1sjson.result_count

  foreach ($t1 in $t1sjson.results) {
    
    $t1id = $t1.id
    
    Write-Host "tier-1:"$t1id 
    
    $t1lss = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s/$t1id/locale-services" -Method 'GET' -Headers $headers 
 
    $t1lssjson = $t1lss | ConvertFrom-Json 

    if ($t1lssjson.result_count -eq "null") {

      Write-Host "No Services Found"} else {

        foreach ($t1ls in $t1lssjson.results ) {

          $t1lsid = $t1ls.id

          try {
          
            $t1mc = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s/$t1id/locale-services/$t1lsid/multicast" -Method 'GET' -Headers $headers 
    
          } catch {

            Write-Host "No Multicast Services Found"
            Exit

          }
          
          if ($t1mc) {

            $t1mcjson = $t1mc | ConvertFrom-Json

          }
             
          # Check if status is OK (200)

          if ($t1mc.StatusCode -ne 200) {

            Write-Host "Failed to retrieve Multicast Information"

            Exit
          } 

          # Check if status is Not Found (404)

          if ($t1mc.StatusCode -eq 404) {

            Write-Host "Multicast has not been enabled."

            Exit

          } 

          $t1int = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-1s/$t1id/locale-services/$t1lsid/interfaces" -Method 'GET' -Headers $headers 

          $t1intjson = $t1int | ConvertFrom-Json       
          
          # Check if status is OK (200)

          if ($t1int.StatusCode -ne 200) {

            Write-Host "Failed to retrieve Interface Information"

            Exit

          } else {
              
            if ($t1mcjson.enabled -ne "true") {

              Write-Host "Multicast for"$t1.display_name"is not enabled"

            } else {

              if ($t1mcjson.enabled -eq "true") {

              Write-Host "Multicast Enabled on"$t1.display_name 
                
              }

            }

          }
        }
    }

  }  

}  
