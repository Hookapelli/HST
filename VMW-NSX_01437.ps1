Function fn_VMW-NSX_01437 {
  Write-Host "VMW-NSX_01437" -ForegroundColor Green

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

          } 

          $t0int = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/interfaces" -Method 'GET' -Headers $headers 

          $t0intjson = $t0int | ConvertFrom-Json       
          
          # Check if status is OK (200)

          if ($t0int.StatusCode -ne 200) {

            Write-Host "Failed to retrieve Interface Information"

          } else {
              
            if ($t0mcjson.enabled -ne "true") {

              Write-Host "Multicast for"$t0.display_name"is not enabled so all interfaces should have multicast and PIM disabled"

            } else {

              if ($t0mcjson.enabled -eq "true") {

              Write-Host "Multicast Enabled on"$t0.display_name 
                
              }

            }

          }

          # If Multicast is Desabled on the Interface, PIM must also be disbled on that interface

          $intpim = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/multicast/pim-rp-mappings"-Method 'GET' -Headers $headers
            
          $intpimjson = $intpim | ConvertFrom-Json

          if ($intpimjson.result_count -eq 0) {

            Write-Host "PIM Profile configurd on"$t0.display_name"not found. All interfaces should be Disabled" 

          }

          foreach ($int in $t0intjson.results){

            if ($int.multicast.enabled -ne "true") {$intmc="Disabled"

              Write-Host "Tier-0"$t0.display_name"Interface:"$int.id "Multicast Enabled:"$intmc

            } else {

              $intmc = $int.multicast.enabled

              Write-Host "Tier-0"$t0.display_name"Interface:"$int.id "Multicast Enabled:"$intmc

            }       

        }

      }
       
    }

  }  

}   
