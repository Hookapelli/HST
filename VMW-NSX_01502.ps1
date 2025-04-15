Function fn_VMW-NSX_01502 {
  Write-Host "VMW-NSX_01502" -ForegroundColor Green

   # Set the Headder for all API calls
   $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
   $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
   $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

# Get SNMP Service Informaiton

try { 

  $snmp = Invoke-WebRequest "https://$global:NSXmgr/api/v1/node/services/snmp" -Method 'GET' -Headers $headers  
 
   } catch {

     Write-Host "No SNMP Service Found"

    }
    
    if ($snmp.StatusCode -ne 200) {

      Write-Host "Failed to retrieve SNMP Service Information"

    }

    if ($snmp) {

      $snmpjson = $snmp | ConvertFrom-Json

  }

  $snmpv2 = $snmpjson.service_properties.v2_configured

  Write-Host "SNMP v2:"$snmpv2 # Should be 'false'

}
