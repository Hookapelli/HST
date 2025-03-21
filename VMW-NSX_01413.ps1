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
}
Function fn_VMW-NSX_01413 {
    Write-Host "VMW-NSX_01413" -ForegroundColor Green
    $uri = "https://$global:NSXmgr/api/v1/logical-switches"
    $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
    $response = Invoke-Expression $command | ConvertFrom-Json
    if ($response.result_count -eq "0") { Write-Host "No Segments/Logical Switches Found"} else { 
        foreach ($result in $response.results) {
            Write-Host
            Write-Host $result.display_name
            foreach ($spi in $result.switching_profile_ids) {
                foreach ($key in $spi.key){
                    if ($key -eq 'SpoofGuardSwitchingProfile') {
                        $sgid = $spi.value 
                        $uri = "https://$global:NSXmgr/policy/api/v1/search?query=resource_type:SpoofGuardProfile%20AND%20unique_id:$sgid"
                        $command = "curl -k -s -X GET -H 'Cookie: JSESSIONID=$global:jsessionid' -H 'X-XSRF-TOKEN: $global:xxsrftoken ' $uri --insecure"
                        $response2 = Invoke-Expression $command | ConvertFrom-Json
                        foreach ($result2 in $response2.results) {
                            Write-Host "    Segment ID: $sgid Allow List:"$result2.address_binding_allowlist
                            Write-Host "    Segment ID: $sgid Whitelist:"$result2.address_binding_whitelist
                        }
                    }
                }
            }
        } 
    }  
}           
    

fn_SetVars
fn_RequestNSXToken
fn_VMW-NSX_01413