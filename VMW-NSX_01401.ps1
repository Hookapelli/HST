Function fn_VMW-NSX_01401 {
  Write-Host "VMW-NSX_01401" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  # Get Tier-0s if they exist

  try { 

    $ntp = Invoke-WebRequest "https://$global:NSXmgr/api/v1/node/services/ntp" -Method 'GET' -Headers $headers  

    } catch {

      Write-Host "Error Loading NTP Service"

      Exit

    }
      
    if ($ntp.StatusCode -ne 200) {

      Write-Host "Failed to retrieve NTP Service"

      Exit 

    }

    if ($ntp) {

      $ntpjson = $ntp | ConvertFrom-Json

    }

    if ($ntp.result_count -eq 0) {

      Write-Host "NTP Not Configured" # This is a finding

      Exit

    }

    Write-Host "NTP Configured"   # This should be Configured

    Write-Host "  Service Name:"$ntpjson.service_name 

    Write-Host "  Servers:"$ntpjson.service_properties.servers

}  
