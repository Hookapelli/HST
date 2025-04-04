Function fn_VMW-NSX_01437 {
  Write-Host "VMW-NSX_01437" -ForegroundColor Green
  $uri = "https://$global:NSXmgr/policy/api/v1/infra/tier-0s"
  $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
  $response = Invoke-Expression $command | ConvertFrom-Json
  if ($response.result_count -eq "0") { Write-Host "No T0 Deployed"} else {
    foreach ($result in $response.results){
      $t0id = $result.id
      $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services"
      $command2 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
      $t0lss = Invoke-Expression $command2 | ConvertFrom-Json 
      if ($t0lss.results-ne "0") {
        foreach ($t0ls in $t0lss.results) {
         $t0lsid = $t0ls.id
          $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/multicast"
          $command3 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
          $t0mc = Invoke-Expression $command3 | ConvertFrom-Json
           Write-Host "T0"$result.display_name
          


          $uri =  "https://$global:NSXmgr/policy/api/v1/infra/tier-0s/$t0id/locale-services/$t0lsid/interfaces"
          $command4 = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
          $t0int = Invoke-Expression $command4 | ConvertFrom-Json 
          foreach ($int in $t0int.results){
            if (!$int.multicast.enabled) {$intmc="Disabled"} else {
              $intmc = $int.multicast.enabled
            }
            Write-Host "Interface:" $int.id 
            Write-Host "Multicast Enabled:"$intmc
            Write-Host
          }
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
fn_VMW-NSX_01437
