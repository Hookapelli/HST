Function fn_VMW-NSX_01535 {
  
  Write-Host "VMW-NSX_01535" -ForegroundColor Green

  # Set the Headder for all API calls
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("X-XSRF-TOKEN", $global:xxsrftoken)
  $headers.Add("Cookie", "JSESSIONID=$global:jsessionid")

  try { 

    $switches = Invoke-WebRequest "https://$global:NSXmgr/api/v1/logical-switches" -Method 'GET' -Headers $headers 
  
    } catch {

      Write-Host "No Logical Switches Found"

      Exit

    } 

    if ($switches) {

      $swjson = $switches | ConvertFrom-Json

    }
  
  # Check if status is OK (200)

  if ($switches.StatusCode -ne 200) {

      Write-Host "Failed to retrieve Logical Switches"

      Exit
  }

  if ($swjson.result_count -eq 0) {

      Write-Host "No Logical Switches are deployed. This is Not Applicable."

      Exit

  }

  Write-Host "Logical Switches:"$swjson.result_count

  foreach ($switch in $swjson.results) {

    Write-Host "Switch:"$switch.display_name -ForegroundColor Yellow

    foreach ($swprofile in $switch.switching_profile_ids) {

      $swprofileprofilejson = $swprofile | ConvertTo-Json

      $swkey = $swprofile.key

      if ($swkey -eq "IpDiscoverySwitchingProfile") {

        if ($swprofile.value) {

          $ipid = $swprofile.value

          Write-Host "IPID: $ipid"  -ForegroundColor Yellow

          $ipprofile = Invoke-WebRequest "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:IPDiscoveryProfile%20AND%20unique_id:$ipid" -Method 'GET' -Headers $headers  

          $ipprofilejson = $ipprofile | ConvertFrom-Json

          foreach ($ipdp in $ipprofilejson.results) {

            $arpsnoopingconfig = $ipdp.ip_v4_discovery_options.arp_snooping_config.arp_snooping_enabled # should be 'true'

            $arpbindinglimit = $ipdp.ip_v4_discovery_options.arp_snooping_config.arp_binding_limit # should cmp '1'
            
            $dhcpsnooping4 = $ipdp.ip_v4_discovery_options.dhcp_snooping_enabled # should be 'false'

            $vmtools4 = $ipdp.ip_v4_discovery_options.vmtools_enabled # should be 'false'

            $dhcpsnooping6 = $ipdp.ip_v6_discovery_options.dhcp_snooping_v6_enabled # should be 'false'

            $vmtools6 = $ipdp.ip_v6_discovery_options.vmtools_v6_enabled  # should be 'false'

            Write-Host "  ARP Snooping Enabled:"$arpsnoopingconfig

            Write-Host "  ARP Binding Limit:" $arpbindinglimit

            Write-Host "  DHCP Snooping Enabled (IPv4):" $dhcpsnooping4

            Write-Host "  VM Tools Enabled (IPv4):"$vmtools4

            Write-Host "  DHCP Snooping Enabled (IPv6):" $dhcpsnooping6

            Write-Host "  VM Tools Enabled (IPv6):"$vmtools6

            Write-Host

          }

        }

      }

    }

  }

}
