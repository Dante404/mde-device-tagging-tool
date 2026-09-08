@{
    RootModule        = 'MdeDeviceTagging.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'f9b94efc-1e28-4c6d-9fd3-350f30300f25'
    Author            = 'Angelo Pitarresi'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Angelo Pitarresi. Licensed under the MIT License.'
    Description       = 'Safety-first Microsoft Defender for Endpoint bulk device-tagging utilities.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Import-MdeTargetName'
        'Get-MdeAccessToken'
        'Invoke-MdeApiRequest'
        'Get-MdeMachineInventory'
        'Resolve-MdeMachineTarget'
        'Get-MdeTagPlan'
        'Invoke-MdeDeviceTagging'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('MDE', 'MicrosoftDefender', 'PowerShell', 'Automation', 'EndpointSecurity')
            ProjectUri = 'https://github.com/Dante404/mde-device-tagging-tool'
            LicenseUri = 'https://github.com/Dante404/mde-device-tagging-tool/blob/main/LICENSE'
        }
    }
}
