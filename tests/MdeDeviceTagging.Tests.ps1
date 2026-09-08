#requires -Version 7.2

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../src/MdeDeviceTagging.psd1'
    Import-Module $modulePath -Force
}

Describe 'Import-MdeTargetName' {
    It 'normalizes, ignores comments, and de-duplicates without changing order' {
        $inputFile = Join-Path $TestDrive 'devices.txt'
        @(
            '# sample'
            'HOST-001'
            ''
            'host-001.'
            'server-002.lab.example'
        ) | Set-Content -LiteralPath $inputFile

        $result = @(Import-MdeTargetName -Path $inputFile)

        $result | Should -HaveCount 2
        $result[0] | Should -Be 'host-001'
        $result[1] | Should -Be 'server-002.lab.example'
    }
}

Describe 'Get-MdeAccessToken' {
    InModuleScope MdeDeviceTagging {
        It 'polls a pending device-code sign-in and returns only the access token' {
            $script:identityCall = 0
            Mock Start-Sleep
            Mock Invoke-RestMethod {
                $script:identityCall++
                if ($script:identityCall -eq 1) {
                    return [pscustomobject]@{
                        device_code = 'synthetic-device-code'
                        expires_in  = 900
                        interval    = 1
                        message     = 'Use the synthetic code to sign in.'
                    }
                }

                if ($script:identityCall -eq 2) {
                    return [pscustomobject]@{
                        error = 'authorization_pending'
                    }
                }

                [pscustomobject]@{
                    access_token = 'synthetic-access-token'
                }
            }

            $result = Get-MdeAccessToken `
                -TenantId 'tenant.example' `
                -ClientId '11111111-1111-1111-1111-111111111111' `
                6>$null

            $result | Should -Be 'synthetic-access-token'
            Should -Invoke Invoke-RestMethod -Times 3 -Exactly
            Should -Invoke Start-Sleep -Times 2 -Exactly
        }
    }
}

Describe 'Resolve-MdeMachineTarget' {
    BeforeAll {
        $machines = @(
            [pscustomobject]@{
                id              = 'machine-old'
                computerDnsName = 'host-001.lab.example'
                lastSeen        = '2026-08-01T10:00:00Z'
                machineTags     = @()
            }
            [pscustomobject]@{
                id              = 'machine-new'
                computerDnsName = 'host-001.corp.example'
                lastSeen        = '2026-08-31T10:00:00Z'
                machineTags     = @('Existing')
            }
            [pscustomobject]@{
                id              = 'machine-two'
                computerDnsName = 'server-002.lab.example'
                lastSeen        = '2026-08-30T10:00:00Z'
                machineTags     = @()
            }
        )
    }

    It 'matches an exact FQDN' {
        $result = Resolve-MdeMachineTarget `
            -TargetName 'server-002.lab.example' `
            -Machines $machines

        $result.Status | Should -Be 'Matched'
        $result.Machine.id | Should -Be 'machine-two'
    }

    It 'reports an ambiguous short name instead of guessing' {
        $result = Resolve-MdeMachineTarget -TargetName 'host-001' -Machines $machines

        $result.Status | Should -Be 'Ambiguous'
        $result.CandidateCount | Should -Be 2
        $result.Machine | Should -BeNullOrEmpty
    }

    It 'uses a domain suffix to resolve a short name safely' {
        $result = Resolve-MdeMachineTarget `
            -TargetName 'host-001' `
            -Machines $machines `
            -DomainSuffix 'lab.example'

        $result.Status | Should -Be 'Matched'
        $result.Machine.id | Should -Be 'machine-old'
    }

    It 'selects the most recently seen match only when explicitly requested' {
        $result = Resolve-MdeMachineTarget `
            -TargetName 'host-001' `
            -Machines $machines `
            -SelectNewestMatch

        $result.Status | Should -Be 'MatchedNewest'
        $result.Machine.id | Should -Be 'machine-new'
    }
}

Describe 'New-MdeTagPlan' {
    BeforeAll {
        $machines = @(
            [pscustomobject]@{
                id              = 'one'
                computerDnsName = 'one.lab.example'
                lastSeen        = '2026-08-31T10:00:00Z'
                machineTags     = @('Pilot')
            }
            [pscustomobject]@{
                id              = 'two'
                computerDnsName = 'two.lab.example'
                lastSeen        = '2026-08-31T09:00:00Z'
                machineTags     = @()
            }
        )
    }

    It 'does not add an existing tag again' {
        $plan = @(New-MdeTagPlan `
                -TargetName 'one.lab.example' `
                -Machines $machines `
                -Tag 'Pilot' `
                -Action Add)

        $plan[0].Status | Should -Be 'NoChange'
    }

    It 'plans a missing tag addition' {
        $plan = @(New-MdeTagPlan `
                -TargetName 'two.lab.example' `
                -Machines $machines `
                -Tag 'Pilot' `
                -Action Add)

        $plan[0].Status | Should -Be 'Planned'
    }

    It 'does not remove a tag that is already absent' {
        $plan = @(New-MdeTagPlan `
                -TargetName 'two.lab.example' `
                -Machines $machines `
                -Tag 'Pilot' `
                -Action Remove)

        $plan[0].Status | Should -Be 'NoChange'
    }
}

Describe 'Get-MdeMachineInventory' {
    InModuleScope MdeDeviceTagging {
        It 'continues beyond the first page' {
            $script:pageCall = 0
            Mock Invoke-MdeApiRequest {
                $script:pageCall++
                if ($script:pageCall -eq 1) {
                    return [pscustomobject]@{
                        value = @(
                            [pscustomobject]@{ id = 'one' }
                            [pscustomobject]@{ id = 'two' }
                        )
                    }
                }

                [pscustomobject]@{
                    value = @([pscustomobject]@{ id = 'three' })
                }
            }

            $result = @(Get-MdeMachineInventory -AccessToken 'synthetic-token' -PageSize 2)

            $result | Should -HaveCount 3
            Should -Invoke Invoke-MdeApiRequest -Times 2 -Exactly
        }
    }
}

Describe 'Invoke-MdeDeviceTagging' {
    InModuleScope MdeDeviceTagging {
        BeforeEach {
            Mock Get-MdeMachineInventory {
                @(
                    [pscustomobject]@{
                        id              = 'machine-one'
                        computerDnsName = 'one.lab.example'
                        lastSeen        = '2026-08-31T10:00:00Z'
                        machineTags     = @()
                    }
                )
            }
            Mock Invoke-MdeApiRequest { [pscustomobject]@{} }
        }

        It 'makes no POST request when DryRun is true' {
            $result = @(Invoke-MdeDeviceTagging `
                    -TargetName 'one.lab.example' `
                    -Tag 'Pilot' `
                    -Action Add `
                    -AccessToken 'synthetic-token' `
                    -DryRun $true)

            $result[0].Status | Should -Be 'DryRun'
            Should -Invoke Invoke-MdeApiRequest `
                -ParameterFilter { $Method -eq 'Post' } `
                -Times 0 `
                -Exactly
        }

        It 'makes one POST request after live mode and confirmation are explicit' {
            $result = @(Invoke-MdeDeviceTagging `
                    -TargetName 'one.lab.example' `
                    -Tag 'Pilot' `
                    -Action Add `
                    -AccessToken 'synthetic-token' `
                    -DryRun:$false `
                    -WriteDelaySeconds 0 `
                    -Confirm:$false)

            $result[0].Status | Should -Be 'Succeeded'
            Should -Invoke Invoke-MdeApiRequest `
                -ParameterFilter {
                    $Method -eq 'Post' -and
                    $Body.Value -eq 'Pilot' -and
                    $Body.Action -eq 'Add'
                } `
                -Times 1 `
                -Exactly
        }
    }
}
