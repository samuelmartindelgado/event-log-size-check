BeforeAll {
    $script:modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'lib' | Join-Path -ChildPath 'EventLogSizeCheck.psm1'
    Import-Module -Name $script:modulePath -Force
}

Describe 'EventLogSizeCheck' {

    BeforeAll {
        function New-FakeLog {
            param(
                [string]$LogName = 'System',
                [bool]$IsEnabled = $true,
                [double]$MaxSizeMB = 20,
                [double]$CurrentSizeMB = 20,
                [long]$EventCount = 1000,
                [string]$LogMode = 'Circular',
                [double]$DaysCovered = 1
            )

            return [pscustomobject]@{
                LogName         = $LogName
                IsEnabled       = $IsEnabled
                MaxSizeMB       = $MaxSizeMB
                CurrentSizeMB   = $CurrentSizeMB
                EventCount      = $EventCount
                LogMode         = $LogMode
                OldestEventTime = (Get-Date).AddDays(-$DaysCovered)
                DaysCovered     = $DaysCovered
                Skipped         = $false
                Note            = ''
            }
        }
    }

    Context 'Get-LogStatus' {

        It 'marca Alta si el registro está deshabilitado' {
            $result = Get-LogStatus -InputObject (New-FakeLog -IsEnabled $false) -MinDays 7

            $result.Estado | Should -Be 'Alta'
            $result.Detalle | Should -Match 'deshabilitado'
        }

        It 'marca Alta si Retain está lleno y dejará de registrar' {
            $result = Get-LogStatus -InputObject (New-FakeLog -LogMode 'Retain' -MaxSizeMB 20 -CurrentSizeMB 20) -MinDays 7

            $result.Estado | Should -Be 'Alta'
            $result.Detalle | Should -Match 'Retain'
        }

        It 'marca Aviso si el registro circular está lleno y solo cubre 0,5 días' {
            $result = Get-LogStatus -InputObject (New-FakeLog -LogMode 'Circular' -MaxSizeMB 20 -CurrentSizeMB 20 -DaysCovered 0.5) -MinDays 7

            $result.Estado | Should -Be 'Aviso'
            $result.Detalle | Should -Match 'Solo guarda 12 horas de historia'
        }

        It 'marca OK si el registro es sano' {
            $result = Get-LogStatus -InputObject (New-FakeLog -LogMode 'Circular' -MaxSizeMB 128 -CurrentSizeMB 40 -DaysCovered 30) -MinDays 7

            $result.Estado | Should -Be 'OK'
        }

        It 'marca Aviso si el tamaño máximo es pequeño en un registro normal' {
            $result = Get-LogStatus -InputObject (New-FakeLog -MaxSizeMB 20 -CurrentSizeMB 5 -DaysCovered 30) -MinDays 7

            $result.Estado | Should -Be 'Aviso'
            $result.Detalle | Should -Match 'por debajo'
        }

        It 'marca Aviso si Security tiene menos de 64 MB' {
            $result = Get-LogStatus -InputObject (New-FakeLog -LogName 'Security' -MaxSizeMB 32 -CurrentSizeMB 5 -DaysCovered 30) -MinDays 7

            $result.Estado | Should -Be 'Aviso'
            $result.Detalle | Should -Match '64 MB recomendados'
        }

        It 'incluye un comando wevtutil de ejemplo sin ejecutarlo' {
            $result = Get-LogStatus -InputObject (New-FakeLog -MaxSizeMB 20 -CurrentSizeMB 20 -DaysCovered 0.5) -MinDays 7

            $result.Solucion | Should -Match 'wevtutil sl "System" /ms:'
        }

        It 'acepta un diccionario como entrada simulada' {
            $log = @{
                LogName       = 'Application'
                IsEnabled     = $true
                MaxSizeMB     = 200
                CurrentSizeMB = 10
                EventCount    = 50
                LogMode       = 'Circular'
                DaysCovered   = 20
            }

            $result = Get-LogStatus -InputObject $log -MinDays 7

            $result.Comprobacion | Should -Be 'Registro: Application'
            $result.Estado | Should -Be 'OK'
        }
    }

    Context 'Get-SuggestedLogSize' {

        It 'calcula y redondea hacia arriba a múltiplos de 64 MB' {
            $suggested = Get-SuggestedLogSize -CurrentSizeMB 20 -DaysCovered 0.5 -MinDays 7

            $suggested | Should -Be 320
            ($suggested % 64) | Should -Be 0
        }

        It 'aplica el mínimo recomendado de 32 MB para registros normales' {
            Get-SuggestedLogSize -CurrentSizeMB 0 -DaysCovered 0 -MinDays 7 | Should -Be 32
        }

        It 'aplica el mínimo recomendado de 64 MB para Security' {
            Get-SuggestedLogSize -CurrentSizeMB 0 -DaysCovered 0 -MinDays 7 -IsSecurity | Should -Be 64
        }

        It 'no baja del mínimo cuando la cobertura ya es suficiente' {
            Get-SuggestedLogSize -CurrentSizeMB 200 -DaysCovered 60 -MinDays 7 | Should -Be 64
        }
    }

    Context 'Get-EventLogCoverage' {

        It 'normaliza datos simulados recibidos con -InputObject' {
            $coverage = Get-EventLogCoverage -LogName 'System' -InputObject @{
                LogName       = 'System'
                IsEnabled     = $true
                MaxSizeMB     = 64
                CurrentSizeMB = 10
                EventCount    = 500
                LogMode       = 'Circular'
                DaysCovered   = 3
            }

            $coverage.LogName | Should -Be 'System'
            $coverage.DaysCovered | Should -Be 3
            $coverage.Skipped | Should -BeFalse
        }

        It 'lee un registro real sin lanzar excepción' {
            { Get-EventLogCoverage -LogName 'System' } | Should -Not -Throw

            $coverage = Get-EventLogCoverage -LogName 'System'
            $coverage.LogName | Should -Be 'System'
            $coverage.Skipped | Should -BeFalse
        }
    }

    Context 'Test-PowerShellLogging' {

        It 'devuelve Aviso si ScriptBlockLogging no está activo' {
            $result = Test-PowerShellLogging -EnableScriptBlockLogging 0

            $result.Estado | Should -Be 'Aviso'
            $result.Detalle | Should -Match 'sin esto no se ve qué scripts se ejecutaron'
        }

        It 'devuelve OK si ScriptBlockLogging está activo' {
            $result = Test-PowerShellLogging -EnableScriptBlockLogging 1

            $result.Estado | Should -Be 'OK'
        }

        It 'lee la directiva real sin lanzar excepción' {
            { Test-PowerShellLogging } | Should -Not -Throw
        }
    }

    Context 'Export-EventLogSizeReport' {

        It 'escribe event-log-size.json y report.html con los textos escapados' {
            $findings = @(
                [pscustomobject]@{
                    Comprobacion = '<script>alert(1)</script>'
                    Estado       = 'Alta'
                    Detalle      = 'Detalle con & y <b>etiquetas</b>'
                    Valor        = '20 MB'
                    Recomendado  = '64 MB'
                    Solucion     = 'wevtutil sl "System" /ms:67108864'
                }
            )
            $outputDir = Join-Path -Path $TestDrive -ChildPath 'salida'

            $result = Export-EventLogSizeReport -Findings $findings -OutputPath $outputDir -Notes @('Nota <de> prueba') -MinDays 7

            Test-Path -LiteralPath $result.Json | Should -BeTrue
            Test-Path -LiteralPath $result.Html | Should -BeTrue

            $html = Get-Content -LiteralPath $result.Html -Raw
            $html | Should -Not -Match '<script>'
            $html | Should -Match '&lt;script&gt;'
            $html | Should -Match 'prefers-color-scheme'

            $json = Get-Content -LiteralPath $result.Json -Raw | ConvertFrom-Json
            $json.Resumen.Alta | Should -Be 1
            $json.Hallazgos[0].Comprobacion | Should -Be '<script>alert(1)</script>'
        }
    }
}

Describe 'Get-SuggestedLogSize con volumen anormal' {
    It 'no recomienda más de 1 GB aunque el registro solo cubra minutos' {
        Get-SuggestedLogSize -CurrentSizeMB 15 -DaysCovered 0.0014 -MinDays 7 | Should -Be 1024
    }
}
