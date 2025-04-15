<#

Include this file to the end of the control you're trying to run.

You can stack the controlls into a single file.

Modify the end of this script to call each function in the script.

#>

Function fn_SetVars {
  $global:NSXmgr = 'lm-mgt-paris.corp.vmbeans.com'
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
  Write-Host "-------------------------------------------------------"
  Write-Host
}
fn_SetVars
fn_RequestNSXToken
fn_VMW-NSX_
