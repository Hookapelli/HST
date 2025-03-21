Function fn_SetVars {
  $global:NSXmgr = '10.100.0.31'
  $global:NSXTAdminUser = 'admin'
  $global:NSXTAdminPass = '123!@#qweQWEasdASD'
}

Function fn_RequestNSXToken {
  Connect-NsxServer $global:NSXmgr -User $global:NSXTAdminUser -Password $global:NSXTAdminPass
  Write-Host "Preparing NSX-T Manager API Token..." -ForegroundColor Green

  # Execute curl Command and Capture Output with Headers
  $url = "https://$global:NSXmgr/api/session/create"
  $command = "curl -k -s -D -c -X POST -d 'j_username=$global:NSXTAdminUser&j_password=$global:NSXTAdminPass' -i 2>&1 $url --insecure"
  $responseString = Invoke-Expression $command

  # Extract JSESSIONID from Header
  $regex = [regex]::Match($responseString, "JSESSIONID=([\w\d]{32})")

  # Check if a Match Was Found
  if ($regex.Success) {
      $global:jsessionid = $regex.Groups[1].Value
  } else {
      Write-Output "JSESSIONID not found or not enough characters available."
  }

  # Extract X-XSRF-TOKEN from Headers
  $regex = [regex]::Match($responseString, "x-xsrf-token:\s*([\w\d-]+)")

  # Check if a Match Was Found
  if ($regex.Success) {
    $global:xxsrftoken = $regex.Groups[1].Value
  } else {
      Write-Output "X-XSRF-TOKEN not found or not enough characters available."
  }

  Write-Host "JSESSION:..."$global:jsessionid -ForegroundColor DarkYellow
  Write-Host "X-XSRF-TOKEN:..."$global:xxsrftoken -ForegroundColor DarkYellow
  $uri = "https://$global:NSXmgr/api/v1/aaa/registration-token"
  $command = "curl -k -s -X POST -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken' 'j_username=$global:NSXTAdminUser&j_password=$global:NSXTAdminPass ' $uri --insecure"
  $Response = Invoke-Expression $command
  $Response = $Response | ConvertFrom-Json
  $global:btoken = $Response.token
  Write-Host "Bearer Token: $global:btoken"  -ForegroundColor DarkYellow
  Write-Host "-------------------------------------------------------"
  Write-Host
}
<#Function fn_VMW-NSX_01409 {   # Determine if Logging is Enabled for each DFW Policy
  Write-Host "VMW-NSX_01409" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:SecurityPolicy%20AND%20!id:default-layer2-section"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  foreach ($result in $response.results) {
    Write-Host "Policy ID: $($result.id) : $($result.logging_enabled)"
    
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01412 {   # Determine if Defauly Layer 3 Rule is configured to DROP
  Write-Host "VMW-NSX_01412" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  Write-Host "Defauly Layer 3 Rule: "$response.action
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01413 {   # Determine if SpoofGuard is ENABLED on DFW 
  Write-Host "VMW-NSX_01413" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/logical-switches"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  if ($response.result_count -eq "0") {
    Write-Host "No Logical Switches Found"
  } else {
    <#foreach ($switch in $response.results) {
      $uri = "https://$global:NSXmgr/api/v1/logical-switches/policy/api/v1/search/query?query=resource_type:SpoofGuardProfile%20AND%20unique_id:#{sgid}" 

    }#>
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}#>
Function fn_VMW-NSX_01414 {   # Verify Logs are being sent to a central log server 
  Write-Host "VMW-NSX_01414" -ForegroundColor Green
  # Is Syslog Running?
  $uri = "https://$global:NSXmgr/api/v1/node/services/syslog/status"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Syslog Service: :"$response.runtime_state

  # Perform API Call to get SysLog Servers
  $uri = "https://$global:NSXmgr/api/v1/node/services/syslog/exporters"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command  | ConvertFrom-Json
  if (!$response.results) { Write-Host "No Syslog Servers Found"} else {
    foreach ($result in $response.results) {
      Write-Output "SysLog Server: $($result.server) - $($result.level)"
    }
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01421 {   # Aslo Supports VMW-NSX_01525, VMW-NSX_01526, VMW-NSX_01527, VMW-NSX_01528, VMW-NSX_01530  
  Write-Host "VMW-NSX_014 & Others" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/node/aaa/auth-policy"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json -Depth 10
  Write-Host "VMW-NSX_01421 - Minimum Password Length:" $response.minimum_password_length
  Write-Host "VMW-NSX_01525 - Enforce Uppercase:" $response.upper_chars 
  Write-Host "VMW-NSX_01526 - Enforce Lowercase:" $response.lower_chars
  Write-Host "VMW-NSX_01527 - Enforce Numeric Character:" $response.digits
  Write-Host "VMW-NSX_01528 - Enforce Special Characters:" $response.special_chars
  Write-Host "VMW-NSX_01530 - Enforce  Unique Password Change:" $response.max_repeats
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01422 {   # Verify NSX Controller is part of a cluster
  Write-Host "VMW-NSX_01422" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/api-virtual-ip"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.ip_address -eq "0.0.0.0") { Write-Host "No Cluster Configured"} else {
    Write-Host "Cluster Configured on IP: "$response.ip_address
  }
  if ($response.ip6_address -eq "::") { Write-Host "No IPv6 Cluster Configured"} else {
    Write-Host "Cluster Configured on IPv6: "$response.ip6_address
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01423 {
  Write-Host "VMW-NSX_01423" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/api-service"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "API Rate Limit:" $response.client_api_rate_limit
  Write-Host "API Concurrency Limit:" $response.global_api_concurrency_limit
  Write-Host "Global API Limit:" $response.client_api_concurrency_limit
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01429 {
Write-Host "VMW-NSX_01429" -ForegroundColor Green
$uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
$command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
$response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Configured"} else {
  <#  
    # Get t01id of each T0
    https://$global:NSXmanager/policy/api/v1/infra/tier-0s

      # For EACH T0 Get the list of Firewall Policies
      https://$global:NSXmgr//policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall

        # For EACH FirewallPolicy get the list of Rules and capture the Rule ID

          # For EACH Rule ID verify logging is enabled
            # logged -eq 'true'
  #>
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01430 {
  Write-Host "VMW-NSX_01430" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:TransportNode%20AND%20node_deployment_info.resource_type:EdgeNode"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No Edge Node Transports Deployed"} else {
    <# 
      # Get the tnid for each Transport Node

        # For EACG EdgeNode: https://$global:NSXmgr/api/v1/transport-nodes/#{tnid}/node/services/syslog/exporters

          # For EACH 'tnid':
            # level -eq  'INFO'
            # protocol -like ['TCP', 'TLS', 'LI-TLS'
            # server -eq input('syslogServers')}" }
    #> 
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01431 {
  Write-Host "VMW-NSX_01431"  -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-1s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T1 Deployed"} else {

    # For each T1R: 
      # https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier1-#{t1id}/rules/default_rule
        # action -ne 'ALLOW'
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}

Function fn_VMW-NSX_01432 {
  Write-Host "VMW-NSX_01432" -ForegroundColor Green
  # Perform API Call 
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Configured"} else {

    # For each T0R: https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier0-#{t0id}/rules/default_rule
      # action -ne 'ALLOW'
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}

  <# VMW-NSX_01437
    #Get t01d of each T0
    https://$global:NSXmanager/policy/api/v1/infra/tier-0s

      # Get locale-services ID for each T0
      https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services

        # See if multicast is enabled on each the T0s
        https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/multicast

        # Get all T0 interfaces
        https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/interfaces
  #>  

  <# VMW-NSX_01453
    # Get list of T0s to provide t01d
    https://$global:NSXmanager/policy/api/v1/infra/tier-0s

      # Get T0 flood-protection profile binding of each T0
      https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/flood-protection-profile-bindings/default

      # Get a list of Flood Protection Profiles
      https://$global:NSXmgr/policy/api/v1/searchpuery?query=resource_type:GatewayFloodProtectionProfile

      # Cycle through each GFPP and verify settings
      https://$global:NSXmgr/policy/api/v1/infra/flood-protection-profiles/#{gfppid}
          # udp_active_flow_limit -ne null
          # icmp_active_flow_limit -ne null
          # tcp_half_open_conn_limit -ne null
          # other_active_conn_limit -ne null
  #>

  <# VMW-NSX_01460 & VMW-NSX_01470
    # Get list of T0s to provide t01d
    https://$global:NSXmanager/policy/api/v1/infra/tier-0s

    # Get locale-services ID for each T0
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services   

    # Check for BGP Enabled on each T0
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp   

      # Verify BGP Max Routes are configured for each T0 (VMW-NSX_01460)
      # Verify BGP Encryption is enabled for each T0 (VMW-NSX_01470) 
      https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp/neighbors   
  #>

  <# VMW-NSX_01469
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/interfaces
  #>

  <# VMW-NSX_01494
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/search.query?query=resource_type:GatewayPolicy%20AND%20category:SharedPreRules

    https://$global:NSXmgr/policy/api/v1#{sharedpolpath}

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall  <--- This one has more logic to work out. Looking for "/infra/services/ICMP_Destination_Unreachable"
  #>

  <# VMW-NSX_01495
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/search/puery?query=resource_type:Service%20AND%20service_entries.icmp_type:18

    https://$global:NSXmgr/policy/api/v1/search/puery?query=resource_type:GatewayPolicy%20AND%20category:SharedPreRules

    https://$global:NSXmgr//policy/api/v1#{sharedpolpath}

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall  <--- This one has more logic to work out. Looking for cmp ALLOW
  #>

  <# VMW-NSX_01495
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/search/puery?query=resource_type:GatewayPolicy%20AND%20category:SharedPreRules

    https://$global:NSXmgr//policy/api/v1#{sharedpolpath}   <-- logic looking for '/infra/services/ICMP_Redirect'

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall  <--- This one has more logic to work out. Looking '/infra/services/ICMP_Redirect'
  #>

  <# VMW-NSX_01503
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s
  #>

  <# VMW-NSX_01504
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp/neighbors

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf/areas
  #>

  <# VMW-NSX_01505
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/multicast
  #>

    <# VMW-NSX_01507
    https://$global:NSXmgr/policy/api/v1/infra/tier-1s

    https://$global:NSXmgr/policy/api/v1/infra/tier-1s/#{t1id}/locale-services

    https://$global:NSXmgr/policy/api/v1/infra/tier-1s/#{t1id}/locale-services/#{t1lsid}/multicast
  #>  

  <# VMW-NSX_01511
    https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:TransportNode%20AND%20node_deployment_info.resource_type:EdgeNode

    https://$global:NSXmgr/api/v1/transport-nodes/#{tnid}/node/services/syslog/exporters
  #>

  <# VMW-NSX_01514
    https://$global:NSXmgr/policy/api/v1/infra/tier-1s

    https://$global:NSXmgr/policy/api/v1/infra/tier-1s/#{t1id}/gateway-firewall
  #>

  <# VMW-NSX_01515
    https://$global:NSXmgr/policy/api/v1/infra/tier-1s

    https://$global:NSXmgr/policy/api/v1/infra/tier-1s/#{t1id}/flood-protection-profile-bindings/default

    https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:GatewayFloodProtectionProfile

      or https://$global:NSXmgr/policy/api/v1/infra/flood-protection-profiles/#{gfppid}

  #>

<# VMW-NSX_01531
    https://$global:NSXmgr/policy/api/v1/infra/global-config

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

     or https://$global:NSXmgr/policy/api/v1#{t0ndprofile}
  #>

  <# VMW-NSX_01536
    https://$global:NSXmgr/policy/api/v1/infra/tier-0s

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/interfaces

    https://$global:NSXmgr/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf
  #>

Function fn_VMW-NSX_01437 {
  Write-Host "VMW-NSX_01437" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host $response
  if ($response.result_count -eq "0") { Write-Host "No T0 Configured"} else {
  # For each T1R: https://$global:NSXmgr/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier0-#{t0id}/rules/default_rule
  }
Write-Host ""
} 
Function fn_VMW-NSX_01452 {
  Write-Host "VMW-NSX_01452" 
  $uri = "https://$global:NSXmgr/policy/api/v1/search/query?query=resource_type:DistributedFloodProtectionProfile"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No DFW Configured"} else {
    <# For Each DFW get: 
          $response.enable_syncache
          $response.enable_rst_spoofing
          $response.udp_active_flow_limit
          $response.icmp_active_flow_limit
          $response.tcp_half_open_conn_limit
          $response.other_active_conn_limit
    #>
  }
}
Function fn_VMW-NSX_01465 { 
  Write-Host "VMW-NSX_01465" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/node"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Timezone: "$response.timezone
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01466 { 
  Write-Host "VMW-NSX_01466" -ForegroundColor Green
  try {
    $command= "curl -k -v https://$global:NSXmgr 2>&1 | Select-String ""issuer"""
    $response = Invoke-Expression $command
    Write-Host "Issued By: "$response
    } catch {
        Write-Output "Error: $_"
    }
  Write-Host "-------------------------------------------------------"
  Write-Host
}

Function fn_VMW-NSX_01468 { 
  Write-Host "VMW-NSX_01468" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/backups/config"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  Write-Host "Back-Up Enabled: "$response.backup_enabled
  Write-Host "-------------------------------------------------------"
  Write-Host
}

Function fn_VMW-NSX_01477 {
  Write-Host "VMW-NSX_01477" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/node/services/ssh/status"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "SSH Service: "$response.runtime_state
  $uri = "https://$global:NSXmgr/api/v1/node/services/ssh"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Start on Boot: "$response.service_properties.start_on_boot
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01499 { 
  Write-Host "VMW-NSX_01499" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/cluster/api-service"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Session Timeout: "$response.session_timeout
  $uri = "https://$global:NSXmgr/api/v1/node"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  Write-Host "Client Timeout: "$response.cli_timeout
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01502 {
  Write-Host "VMW-NSX_01502" -ForegroundColor Green
  # Perform API Call 
  $uri = "https://$global:NSXmgr/api/v1/node/services/snmp"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  Write-Host "SNMP v2: "$response.service_properties.v2_configured
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01509 {
  Write-Host "VMW-NSX_01509" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/v1/upgrade/nodes"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  foreach ($result in $response.results) {
    if ($result.component_version -ne "Pending") {
      Write-Host "NSX Version: "$($result.display_name)   $($result.component_version)
    }
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}
Function fn_VMW-NSX_01525 {
  Write-Host "VMW-NSX_01525" -ForegroundColor Green
  # Perform API Call 
  $uri = "https://$global:NSXmgr/api/v1/node/aaa/auth-policy"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertTo-Json -Depth 10
  Write-Host $response
  Write-Host "-------------------------------------------------------"
  Write-Host
}

Function fn_VMW-NSX_01535 {
  Write-Host "VMW-NSX_01535" -ForegroundColor Green
  # Perform API Call 
  $uri = "https://$global:NSXmgr/api/v1/logical-switches"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No Logical Switches Configured Configured"} else {
    # if exists do https://$global:NSXmgr/policy/api/v1/search/query?query=(resource_type:IPDiscoveryProfile%20AND%20unique_id:#{ipid}
        # ip_v4_discovery_options', 'arp_snooping_config', 'arp_snooping_enabled']) { should cmp 'true' }
        # ip_v4_discovery_options', 'arp_snooping_config', 'arp_binding_limit']) { should cmp '1' }
        # ip_v4_discovery_options', 'dhcp_snooping_enabled']) { should cmp 'false' }
        # ip_v4_discovery_options', 'vmtools_enabled']) { should cmp 'false' }
        # ip_v6_discovery_options', 'dhcp_snooping_v6_enabled']) { should cmp 'false' }
        # ip_v6_discovery_options', 'vmtools_v6_enabled']) { should cmp 'false' }
  }
  Write-Host "-------------------------------------------------------"
  Write-Host
}


fn_SetVars
fn_RequestNSXToken
fn_VMW-NSX_01409
fn_VMW-NSX_01412
fn_VMW-NSX_01413 # Need to Drill into JSON and cycle through Switches. 
fn_VMW-NSX_01414
fn_VMW-NSX_01421 # Supports VMW-NSX_01525, VMW-NSX_01526, VMW-NSX_01527, VMW-NSX_01528, VMW-NSX_01530
fn_VMW-NSX_01422
fn_VMW-NSX_01423
fn_VMW-NSX_01429
fn_VMW-NSX_01430 # Need to Drill into JSON and cycle through EdgeNodes
fn_VMW-NSX_01431
fn_VMW-NSX_01432 # Supports VMW-NSX_01437, VMW-NSX_01453, VMW-NSX_01460, VMW-NSX_01469 
fn_VMW-NSX_01452 
fn_VMW-NSX_01465
fn_VMW-NSX_01466 
fn_VMW-NSX_01468 
fn_VMW-NSX_01477
fn_VMW-NSX_01499
fn_VMW-NSX_01502
fn_VMW-NSX_01509
fn_VMW-NSX_01535
