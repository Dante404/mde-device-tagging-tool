Set-StrictMode -Version Latest

$script:DefaultApiBaseUri = 'https://api.security.microsoft.com'
$script:DefaultScope = 'https://api.securitycenter.microsoft.com/.default'

function Import-MdeTargetName {
    <#
    .SYNOPSIS
    Loads, normalizes, and de-duplicates target computer names from a text file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$Path
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
        $name = $line.Trim().TrimEnd('.')

        if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('#')) {
            continue
        }

        if ($seen.Add($name)) {
            $name.ToLowerInvariant()
        }
    }
}

function Get-MdeAccessToken {
    <#
    .SYNOPSIS
    Obtains a delegated Microsoft Defender for Endpoint token with device-code authentication.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -ne [guid]::Empty })]
        [guid]$ClientId,

        [ValidateNotNullOrEmpty()]
        [string]$Scope = $script:DefaultScope
    )

    $tenant = [Uri]::EscapeDataString($TenantId)
    $deviceCodeEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/devicecode"
    $tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"

    $deviceResponse = Invoke-RestMethod `
        -Uri $deviceCodeEndpoint `
        -Method Post `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            client_id = $ClientId
            scope     = $Scope
        } `
        -ErrorAction Stop

    foreach ($requiredProperty in @('device_code', 'expires_in', 'interval', 'message')) {
        if ($null -eq $deviceResponse.PSObject.Properties[$requiredProperty]) {
            throw "The identity platform response did not include '$requiredProperty'."
        }
    }

    Write-Information ([string]$deviceResponse.message) -InformationAction Continue

    $pollingIntervalSeconds = [Math]::Max(1, [int]$deviceResponse.interval)
    $expiresAt = [DateTimeOffset]::UtcNow.AddSeconds([int]$deviceResponse.expires_in)

    while ([DateTimeOffset]::UtcNow -lt $expiresAt) {
        Start-Sleep -Seconds $pollingIntervalSeconds

        $tokenResponse = Invoke-RestMethod `
            -Uri $tokenEndpoint `
            -Method Post `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = [string]$deviceResponse.device_code
            } `
            -SkipHttpErrorCheck `
            -ErrorAction Stop

        $accessTokenProperty = $tokenResponse.PSObject.Properties['access_token']
        if ($null -ne $accessTokenProperty -and
            -not [string]::IsNullOrWhiteSpace([string]$accessTokenProperty.Value)) {
            return [string]$accessTokenProperty.Value
        }

        $errorProperty = $tokenResponse.PSObject.Properties['error']
        if ($null -eq $errorProperty) {
            throw 'The identity platform returned an unexpected token response.'
        }

        $oauthError = [string]$errorProperty.Value
        switch ($oauthError) {
            'authorization_pending' {
                continue
            }
            'slow_down' {
                $pollingIntervalSeconds += 5
                continue
            }
            'authorization_declined' {
                throw 'Device-code authentication was declined.'
            }
            'bad_verification_code' {
                throw 'The device code was not recognized by the identity platform.'
            }
            'expired_token' {
                throw 'The device code expired before authentication completed.'
            }
            default {
                $descriptionProperty = $tokenResponse.PSObject.Properties['error_description']
                $description = if ($null -eq $descriptionProperty) {
                    'No error description was supplied.'
                }
                else {
                    [string]$descriptionProperty.Value
                }

                throw "Device-code authentication failed ($oauthError): $description"
            }
        }
    }

    throw 'The device code expired before authentication completed.'
}

function Get-MdeRetryDelaySeconds {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [AllowNull()]
        [object]$Response,

        [Parameter(Mandatory)]
        [ValidateRange(0, 20)]
        [int]$Attempt,

        [Parameter(Mandatory)]
        [ValidateRange(1, 60)]
        [int]$InitialRetrySeconds
    )

    if ($null -ne $Response) {
        try {
            $retryAfter = $Response.Headers.RetryAfter

            if ($null -ne $retryAfter.Delta) {
                return [Math]::Max(1, $retryAfter.Delta.TotalSeconds)
            }

            if ($null -ne $retryAfter.Date) {
                $seconds = ($retryAfter.Date.UtcDateTime - [DateTime]::UtcNow).TotalSeconds
                return [Math]::Max(1, $seconds)
            }
        }
        catch {
            Write-Verbose 'The Retry-After header could not be parsed; exponential backoff will be used.'
        }
    }

    $backoff = [Math]::Min(60, $InitialRetrySeconds * [Math]::Pow(2, $Attempt))
    $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000
    $backoff + $jitter
}

function Invoke-MdeApiRequest {
    <#
    .SYNOPSIS
    Calls the Defender for Endpoint API with bounded retry and Retry-After support.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [AllowNull()]
        [hashtable]$Body,

        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 6,

        [ValidateRange(1, 60)]
        [int]$InitialRetrySeconds = 2
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = 'application/json'
    }

    for ($attempt = 0; $attempt -le $MaxRetryCount; $attempt++) {
        try {
            $requestParameters = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $headers
                ErrorAction = 'Stop'
            }

            if ($null -ne $Body) {
                $requestParameters.ContentType = 'application/json'
                $requestParameters.Body = $Body | ConvertTo-Json -Compress
            }

            return Invoke-RestMethod @requestParameters
        }
        catch {
            $response = $null
            $statusCode = 0

            $responseProperty = $_.Exception.PSObject.Properties['Response']
            if ($null -ne $responseProperty) {
                $response = $responseProperty.Value
            }

            if ($null -ne $response) {
                $statusCodeProperty = $response.PSObject.Properties['StatusCode']
                if ($null -ne $statusCodeProperty) {
                    $statusCode = [int]$statusCodeProperty.Value
                }
            }

            $retryable = $statusCode -in @(408, 429, 500, 502, 503, 504)
            if (-not $retryable -or $attempt -ge $MaxRetryCount) {
                throw
            }

            $delay = Get-MdeRetryDelaySeconds `
                -Response $response `
                -Attempt $attempt `
                -InitialRetrySeconds $InitialRetrySeconds

            Write-Warning (
                'Defender API returned HTTP {0}. Retrying in {1:N1} seconds ({2}/{3}).' -f `
                    $statusCode, $delay, ($attempt + 1), $MaxRetryCount
            )
            Start-Sleep -Milliseconds ([int]($delay * 1000))
        }
    }
}

function Get-MdeMachineInventory {
    <#
    .SYNOPSIS
    Retrieves every Defender machine visible to the signed-in user.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateNotNullOrEmpty()]
        [string]$ApiBaseUri = $script:DefaultApiBaseUri,

        [ValidateRange(1, 10000)]
        [int]$PageSize = 1000,

        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 6
    )

    $baseUri = $ApiBaseUri.TrimEnd('/')
    $skip = 0
    $uri = '{0}/api/machines?$top={1}&$skip={2}' -f $baseUri, $PageSize, $skip
    $machines = [System.Collections.Generic.List[object]]::new()

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        Write-Verbose "Retrieving Defender machine page starting at offset $skip."
        $response = Invoke-MdeApiRequest `
            -Uri $uri `
            -Method Get `
            -AccessToken $AccessToken `
            -MaxRetryCount $MaxRetryCount

        if ($null -eq $response) {
            throw "The Defender API returned an empty response for '$uri'."
        }

        $valueProperty = $response.PSObject.Properties['value']
        $page = if ($null -eq $valueProperty) {
            @()
        }
        else {
            @($valueProperty.Value)
        }
        foreach ($machine in $page) {
            $machines.Add($machine)
        }

        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        if ($null -ne $nextLinkProperty -and -not [string]::IsNullOrWhiteSpace($nextLinkProperty.Value)) {
            $uri = [string]$nextLinkProperty.Value
            $skip += $page.Count
        }
        elseif ($page.Count -lt $PageSize) {
            $uri = $null
        }
        else {
            $skip += $PageSize
            $uri = '{0}/api/machines?$top={1}&$skip={2}' -f $baseUri, $PageSize, $skip
        }
    }

    Write-Verbose "Retrieved $($machines.Count) Defender machine records."
    $machines
}

function Resolve-MdeMachineTarget {
    <#
    .SYNOPSIS
    Resolves a short or fully qualified computer name to one Defender machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Machines,

        [AllowEmptyString()]
        [string]$DomainSuffix,

        [switch]$SelectNewestMatch
    )

    $normalizedTarget = $TargetName.Trim().TrimEnd('.').ToLowerInvariant()
    $normalizedDomain = if ([string]::IsNullOrWhiteSpace($DomainSuffix)) {
        ''
    }
    else {
        $DomainSuffix.Trim().Trim('.').ToLowerInvariant()
    }
    $targetIsFqdn = $normalizedTarget.Contains('.')

    $candidates = @(
        foreach ($machine in $Machines) {
            $dnsName = [string]$machine.computerDnsName
            if ([string]::IsNullOrWhiteSpace($dnsName)) {
                continue
            }

            $normalizedDnsName = $dnsName.Trim().TrimEnd('.').ToLowerInvariant()
            $nameMatches = if ($targetIsFqdn) {
                $normalizedDnsName -eq $normalizedTarget
            }
            else {
                $normalizedDnsName.Split('.')[0] -eq $normalizedTarget
            }

            if (-not $nameMatches) {
                continue
            }

            if (-not [string]::IsNullOrWhiteSpace($normalizedDomain)) {
                $domainMatches = $normalizedDnsName.EndsWith(
                    ".$normalizedDomain",
                    [System.StringComparison]::OrdinalIgnoreCase
                )

                if (-not $domainMatches) {
                    continue
                }
            }

            $machine
        }
    )

    if ($candidates.Count -eq 0) {
        return [pscustomobject]@{
            Status         = 'NotFound'
            Machine        = $null
            CandidateCount = 0
            Detail         = 'No accessible Defender machine matched the supplied name.'
        }
    }

    if ($candidates.Count -eq 1) {
        return [pscustomobject]@{
            Status         = 'Matched'
            Machine        = $candidates[0]
            CandidateCount = 1
            Detail         = 'A unique Defender machine was matched.'
        }
    }

    if ($SelectNewestMatch) {
        $selected = $candidates |
            Sort-Object `
                @{ Expression = { [DateTime]$_.lastSeen }; Descending = $true },
                @{ Expression = { [string]$_.id }; Descending = $false } |
            Select-Object -First 1

        return [pscustomobject]@{
            Status         = 'MatchedNewest'
            Machine        = $selected
            CandidateCount = $candidates.Count
            Detail         = "Selected the most recently seen record from $($candidates.Count) matches."
        }
    }

    [pscustomobject]@{
        Status         = 'Ambiguous'
        Machine        = $null
        CandidateCount = $candidates.Count
        Detail         = "Found $($candidates.Count) matching records. Use -DomainSuffix or -SelectNewestMatch."
    }
}

function New-MdeTagPlan {
    <#
    .SYNOPSIS
    Creates an idempotent tag-change plan without making API changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TargetName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Machines,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Tag,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Remove')]
        [string]$Action,

        [AllowEmptyString()]
        [string]$DomainSuffix,

        [switch]$SelectNewestMatch
    )

    foreach ($target in $TargetName) {
        $resolution = Resolve-MdeMachineTarget `
            -TargetName $target `
            -Machines $Machines `
            -DomainSuffix $DomainSuffix `
            -SelectNewestMatch:$SelectNewestMatch

        if ($null -eq $resolution.Machine) {
            [pscustomobject]@{
                InputName      = $target
                DeviceName     = $null
                MachineId      = $null
                LastSeen       = $null
                CandidateCount = $resolution.CandidateCount
                Action         = $Action
                Tag            = $Tag
                Status         = $resolution.Status
                Detail         = $resolution.Detail
            }
            continue
        }

        $machine = $resolution.Machine
        $machineTagsProperty = $machine.PSObject.Properties['machineTags']
        $existingTags = if ($null -eq $machineTagsProperty) {
            @()
        }
        else {
            @($machineTagsProperty.Value)
        }
        $hasTag = $existingTags -contains $Tag
        $changeRequired = ($Action -eq 'Add' -and -not $hasTag) -or
            ($Action -eq 'Remove' -and $hasTag)

        [pscustomobject]@{
            InputName      = $target
            DeviceName     = [string]$machine.computerDnsName
            MachineId      = [string]$machine.id
            LastSeen       = $machine.lastSeen
            CandidateCount = $resolution.CandidateCount
            Action         = $Action
            Tag            = $Tag
            Status         = if ($changeRequired) { 'Planned' } else { 'NoChange' }
            Detail         = if ($changeRequired) {
                $resolution.Detail
            }
            elseif ($Action -eq 'Add') {
                'The device already has this tag.'
            }
            else {
                'The device does not have this tag.'
            }
        }
    }
}

function Invoke-MdeDeviceTagging {
    <#
    .SYNOPSIS
    Plans and optionally performs MDE machine tag changes.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TargetName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Tag,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Remove')]
        [string]$Action,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [bool]$DryRun = $true,

        [AllowEmptyString()]
        [string]$DomainSuffix,

        [switch]$SelectNewestMatch,

        [ValidateNotNullOrEmpty()]
        [string]$ApiBaseUri = $script:DefaultApiBaseUri,

        [ValidateRange(1, 10000)]
        [int]$PageSize = 1000,

        [ValidateRange(0, 60)]
        [double]$WriteDelaySeconds = 3,

        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 6
    )

    $machines = @(Get-MdeMachineInventory `
            -AccessToken $AccessToken `
            -ApiBaseUri $ApiBaseUri `
            -PageSize $PageSize `
            -MaxRetryCount $MaxRetryCount)

    $plan = @(New-MdeTagPlan `
            -TargetName $TargetName `
            -Machines $machines `
            -Tag $Tag `
            -Action $Action `
            -DomainSuffix $DomainSuffix `
            -SelectNewestMatch:$SelectNewestMatch)

    $writeAttemptCount = 0
    foreach ($item in $plan) {
        $result = $item | Select-Object *

        if ($item.Status -ne 'Planned') {
            $result
            continue
        }

        if ($DryRun) {
            $result.Status = 'DryRun'
            $result.Detail = 'No API write was made because DryRun defaults to true.'
            $result
            continue
        }

        $operation = "$Action tag '$Tag'"
        if (-not $PSCmdlet.ShouldProcess($item.DeviceName, $operation)) {
            $result.Status = 'Skipped'
            $result.Detail = 'The change was not approved by ShouldProcess.'
            $result
            continue
        }

        if ($writeAttemptCount -gt 0 -and $WriteDelaySeconds -gt 0) {
            Start-Sleep -Milliseconds ([int]($WriteDelaySeconds * 1000))
        }

        $writeAttemptCount++

        $encodedMachineId = [Uri]::EscapeDataString($item.MachineId)
        $uri = '{0}/api/machines/{1}/tags' -f $ApiBaseUri.TrimEnd('/'), $encodedMachineId
        $body = @{
            Value  = $Tag
            Action = $Action
        }

        try {
            $null = Invoke-MdeApiRequest `
                -Uri $uri `
                -Method Post `
                -AccessToken $AccessToken `
                -Body $body `
                -MaxRetryCount $MaxRetryCount

            $result.Status = 'Succeeded'
            $result.Detail = "Successfully completed: $operation."
        }
        catch {
            $result.Status = 'Failed'
            $result.Detail = $_.Exception.Message
        }

        $result
    }
}

Export-ModuleMember -Function @(
    'Import-MdeTargetName',
    'Get-MdeAccessToken',
    'Invoke-MdeApiRequest',
    'Get-MdeMachineInventory',
    'Resolve-MdeMachineTarget',
    'New-MdeTagPlan',
    'Invoke-MdeDeviceTagging'
)
