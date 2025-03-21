Function fn_VMW-NSX_TEST {   # Determine if Defauly Layer 3 Rule is configured to DROP
  Write-Host "VMW-NSX_01430" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/search?query=resource_type:TransportNode%20AND%20node_deployment_info.resource_type:EdgeNode"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command
  $response = $response | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No Edge Node Transports Deployed"} else {
    foreach ($result in $response.results){
      $tnid = $result.id 
      Write-Host "Edge Node:" $result.display_name   "ID:"$tnid 
      $uri = "https://$global:NSXmgr/api/v1/transport-nodes/$tnid/node/services/syslog/exporters"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure" 
      $tnsyslog = Invoke-Expression $command2 | ConvertFrom-Json
      if ($tnsyslog.result_count -eq "0") {Write-Host "No Syslog Servers Configured"} else {
        foreach ($logserver in $tnsyslog.results){
          Write-Host "   Level: "$logserver.level
          Write-Host "   Protocol: "$logserver.Protocol
          Write-Host "   Server: "$logserver.server
          Write-Host
        }
      }
    }
  }
 }
 
# CUT BELOW HERE ------------------------
Function fn_SetVars {
    $global:NSXmgr = '192.168.50.4'
    $global:NSXTAdminUser = 'admin'
    $global:NSXTAdminPass = 'VMware1!VMware1!'
  }
  
Function fn_RequestNSXToken {
  if (!$global:jsessionid) {
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
  }
  Write-Host "JSESSION:..."$global:jsessionid -ForegroundColor DarkYellow
  Write-Host "X-XSRF-TOKEN:..."$global:xxsrftoken -ForegroundColor DarkYellow
  <#$uri = "https://$global:NSXmgr/api/v1/aaa/registration-token"
  $command = "curl -k -s -X POST -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken' 'j_username=$global:NSXTAdminUser&j_password=$global:NSXTAdminPass ' $uri --insecure"
  $Response = Invoke-Expression $command
  $Response = $Response | ConvertFrom-Json
  $global:btoken = $Response.token
  Write-Host "Bearer Token: $global:btoken"  -ForegroundColor DarkYellow #>
  Write-Host "-------------------------------------------------------"
  Write-Host
}
fn_SetVars
fn_RequestNSXToken
fn_VMW-NSX_TEST
