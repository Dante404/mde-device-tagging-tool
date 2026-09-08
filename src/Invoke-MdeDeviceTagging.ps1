#requires -Version 7.2

<#
.SYNOPSIS
Safely plans and optionally applies Microsoft Defender for Endpoint machine tags.

.DESCRIPTION
Loads target computer names from a text file, retrieves every accessible machine from the
Defender for Endpoint API, resolves each name, and creates an idempotent change plan.
DryRun is true by default. Live changes additionally use PowerShell ShouldProcess.

.PARAMETER TenantId
The Microsoft Entra tenant ID or verified tenant domain.

.PARAMETER ClientId
The application (client) ID of a public-client Entra app registration.

.PARAMETER InputPath
Path to a text file containing one short hostname or FQDN per line. Blank lines and lines
starting with # are ignored.

.PARAMETER Tag
The Microsoft Defender for Endpoint machine tag to add or remove.

.PARAMETER Action
Add or Remove.

.PARAMETER DryRun
Defaults to true. Pass -DryRun:$false to permit live API writes, which remain subject to
ShouldProcess confirmation.

.EXAMPLE
./Invoke-MdeDeviceTagging.ps1 -TenantId '<tenant-id>' -ClientId '<client-id>' `
    -InputPath '../examples/devices.txt' -Tag 'Migration-Pilot' -Action Add

Creates a dry-run plan. No machine tags are changed.

.EXAMPLE
./Invoke-MdeDeviceTagging.ps1 -TenantId '<tenant-id>' -ClientId '<client-id>' `
    -InputPath '../examples/devices.txt' -Tag 'Migration-Pilot' -Action Add `
    -DomainSuffix 'lab.example' -DryRun:$false

Requests confirmation before making live changes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid]$ClientId,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InputPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Tag,

    [Parameter(Mandatory)]
    [ValidateSet('Add', 'Remove')]
    [string]$Action,

    [bool]$DryRun = $true,

    [AllowEmptyString()]
    [string]$DomainSuffix,

    [switch]$SelectNewestMatch,

    [ValidateRange(1, 10000)]
    [int]$PageSize = 1000,

    [ValidateRange(0, 60)]
    [double]$WriteDelaySeconds = 3,

    [ValidateRange(0, 10)]
    [int]$MaxRetryCount = 6,

    [string]$OutputPath
)

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'MdeDeviceTagging.psd1'
Import-Module $modulePath -Force -ErrorAction Stop

$targetNames = @(Import-MdeTargetName -Path $InputPath)
if ($targetNames.Count -eq 0) {
    throw 'The input file did not contain any target computer names.'
}

$accessToken = Get-MdeAccessToken `
    -TenantId $TenantId `
    -ClientId $ClientId

$invokeParameters = @{
    TargetName          = $targetNames
    Tag                 = $Tag
    Action              = $Action
    AccessToken         = $accessToken
    DryRun              = $DryRun
    DomainSuffix        = $DomainSuffix
    SelectNewestMatch   = $SelectNewestMatch
    PageSize            = $PageSize
    WriteDelaySeconds   = $WriteDelaySeconds
    MaxRetryCount       = $MaxRetryCount
}

if ($PSBoundParameters.ContainsKey('WhatIf')) {
    $invokeParameters.WhatIf = $true
}

if ($PSBoundParameters.ContainsKey('Confirm')) {
    $invokeParameters.Confirm = $PSBoundParameters['Confirm']
}

$results = @(Invoke-MdeDeviceTagging @invokeParameters)

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8
}

$results
