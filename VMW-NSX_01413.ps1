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
