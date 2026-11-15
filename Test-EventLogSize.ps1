#Requires -Version 5.1
<#
.SYNOPSIS
    Revisa que los registros de eventos de Windows guarden historia suficiente.
.DESCRIPTION
    Comprueba tamaño máximo, tamaño actual, número de eventos, modo de
    sobrescritura y días de historia de los registros indicados. Muestra
    recomendaciones y comandos de ejemplo, pero NO modifica nada del equipo.
.PARAMETER MinDays
    Cobertura mínima de historia deseada, en días. Por defecto 7.
.PARAMETER LogName
    Registros de eventos que se revisan.
.PARAMETER OutputPath
    Carpeta donde se escriben event-log-size.json y report.html.
.EXAMPLE
    ./Test-EventLogSize.ps1
.EXAMPLE
    ./Test-EventLogSize.ps1 -MinDays 14 -OutputPath ./salida
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MinDays = 7,

    [Parameter()]
    [string[]]$LogName = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-PowerShell/Operational',
        'Windows PowerShell',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    ),

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/EventLogSizeCheck.psm1'
Import-Module -Name $modulePath -Force

$coverageList = New-Object System.Collections.Generic.List[object]
foreach ($currentLogName in $LogName) {
    $coverageList.Add((Get-EventLogCoverage -LogName $currentLogName))
}

$findings = New-Object System.Collections.Generic.List[object]
$notes = New-Object System.Collections.Generic.List[string]

foreach ($coverage in $coverageList) {
    if ($coverage.Skipped) {
        $notes.Add("$($coverage.LogName): $($coverage.Note)")
        continue
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$coverage.Note)) {
        $notes.Add("$($coverage.LogName): $($coverage.Note)")
    }
    $findings.Add((Get-LogStatus -InputObject $coverage -MinDays $MinDays))
}

$findings.Add((Test-PowerShellLogging))

$okCount = @($findings | Where-Object { $_.Estado -eq 'OK' }).Count
$avisoCount = @($findings | Where-Object { $_.Estado -eq 'Aviso' }).Count
$altaCount = @($findings | Where-Object { $_.Estado -eq 'Alta' }).Count

$avisoLabel = 'avisos'
if ($avisoCount -eq 1) {
    $avisoLabel = 'aviso'
}
$altaLabel = 'altas'
if ($altaCount -eq 1) {
    $altaLabel = 'alta'
}

$reportPaths = $null
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportPaths = Export-EventLogSizeReport -Findings $findings.ToArray() -OutputPath $OutputPath -Notes $notes.ToArray() -MinDays $MinDays
}

Write-Host ''
Write-Host ('Revisión de registros de eventos - {0} - {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm'))
Write-Host ('Cobertura mínima deseada: {0} días' -f $MinDays)
Write-Host ''

foreach ($finding in $findings) {
    $color = 'Green'
    if ($finding.Estado -eq 'Aviso') {
        $color = 'Yellow'
    } elseif ($finding.Estado -eq 'Alta') {
        $color = 'Red'
    }

    Write-Host ('[{0}] {1}' -f $finding.Estado, $finding.Comprobacion) -ForegroundColor $color
    Write-Host ('       {0}' -f $finding.Detalle)
    if (-not [string]::IsNullOrWhiteSpace([string]$finding.Recomendado)) {
        Write-Host ('       Recomendado: {0}' -f $finding.Recomendado)
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$finding.Solucion)) {
        Write-Host ('       Solución (ejemplo, no ejecutada): {0}' -f $finding.Solucion)
    }
}

if ($notes.Count -gt 0) {
    Write-Host ''
    Write-Host 'Notas:'
    foreach ($note in $notes) {
        Write-Host ('  - {0}' -f $note)
    }
}

Write-Host ''
Write-Host ('Resumen: {0} OK, {1} {2}, {3} {4}' -f $okCount, $avisoCount, $avisoLabel, $altaCount, $altaLabel)
if ($null -ne $reportPaths) {
    Write-Host ('Informe JSON: {0}' -f $reportPaths.Json)
    Write-Host ('Informe HTML: {0}' -f $reportPaths.Html)
}
Write-Host 'Solo lectura: no se ha modificado ningún registro ni directiva.'

if ($altaCount -gt 0) {
    exit 2
}
if ($avisoCount -gt 0) {
    exit 1
}
exit 0
