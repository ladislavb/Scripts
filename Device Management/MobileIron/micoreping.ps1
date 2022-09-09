<#
    .SYNOPSIS
    MI Core REST API test

    .DESCRIPTION
    PowerShell script to test MobileIron REST API connection
    
    Author: Ladislav Blažek <ladislav@lblazek.cz>
    Copyright: Licensed under the MIT license. See LICENSE in the repository root for license information.
    
#>

$MIAPIServer = Read-Host "MI Core hostname (vsp.acme.com)"
$MIAPIUsername = Read-Host "API Username"
$MIAPIPassword = Read-Host -MaskInput "API Password" 
$MIAPIAdminSpaceID = 1

Try {
    $MIAPIEndPointV1 = "https://" + $MIAPIServer + "/api/v1"
    $MIAPIEndPointV2 = "https://" + $MIAPIServer + "/api/v2"
    $AuthString = ($MIAPIUsername + ":" + $MIAPIPassword)
    $AuthBytes  = [System.Text.Encoding]::Ascii.GetBytes($AuthString)
    $MIAPICredentials = [Convert]::ToBase64String($AuthBytes)
    $MIAPIHeaders = @{
        "X-Requested-With" = "PowerShell"
        "Authorization" = "Basic " + ($MIAPICredentials)
    }
    $Uri = $MIAPIEndPointV2 + "/ping"
    $Response = Invoke-WebRequest -Headers $MIAPIHeaders -Uri $Uri -Method 'Get'
	"<<<<< HTTP RESPONSE: " + $Response.StatusCode
	"Headers: " + (ConvertTo-Json -InputObject $Response.Headers)
	"Content: " + $Response.Content
}
Catch {
    Write-Error "API Connection Failed!"
	$_.Exception
}
