# Módulo de comprobación de cobertura de los registros de eventos de Windows.
# Solo lectura: ninguna función modifica la configuración del equipo.

$script:MaxSuggestedMB = 1024

function Get-SuggestedLogSize {
    <#
    .SYNOPSIS
        Calcula el tamaño recomendado de un registro de eventos en MB.
    .DESCRIPTION
        Aplica la fórmula tamaño actual * (días deseados / días cubiertos), redondea
        hacia arriba a múltiplos de 64 MB y nunca baja del mínimo recomendado
        (64 MB para Security, 32 MB para el resto).
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [double]$CurrentSizeMB,

        [Parameter(Mandatory)]
        [double]$DaysCovered,

        [Parameter(Mandatory)]
        [int]$MinDays,

        [switch]$IsSecurity
    )

    $recommendedMB = 32
    if ($IsSecurity) {
        $recommendedMB = 64
    }

    if ($DaysCovered -le 0 -or $CurrentSizeMB -le 0 -or $MinDays -le 0) {
        return $recommendedMB
    }

    $targetMB = $CurrentSizeMB * ($MinDays / $DaysCovered)
    # Nunca más de 1 GB: si hiciera falta más, el problema es que algo genera
    # demasiados eventos (eso lo avisa Get-LogStatus), no el tamaño.
    $targetMB = [math]::Min($targetMB, $script:MaxSuggestedMB)
    $roundedMB = [int]([math]::Ceiling($targetMB / 64) * 64)
    if ($roundedMB -lt $recommendedMB) {
        $roundedMB = $recommendedMB
    }
    return $roundedMB
}

function Format-CoverageDuration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double]$Days
    )

    if ($Days -lt (1 / 24)) {
        $minutes = [int][math]::Round($Days * 24 * 60)
        if ($minutes -lt 1) {
            $minutes = 1
        }
        if ($minutes -eq 1) {
            return '1 minuto'
        }
        return "$minutes minutos"
    }

    if ($Days -lt 1) {
        $hours = [int][math]::Round($Days * 24)
        if ($hours -lt 1) {
            $hours = 1
        }
        if ($hours -eq 1) {
            return '1 hora'
        }
        return "$hours horas"
    }

    $roundedDays = [math]::Round($Days, 1)
    if ($roundedDays -eq 1) {
        return '1 día'
    }
    return "$roundedDays días"
}

function Get-EventLogCoverage {
    <#
    .SYNOPSIS
        Lee la cobertura de historia de un registro de eventos.
    .DESCRIPTION
        Usa Get-WinEvent -ListLog y Get-WinEvent -MaxEvents 1 -Oldest. Si no puede
        leer el registro devuelve un objeto con Skipped = $true y una nota; nunca
        lanza una excepción. Admite -InputObject con datos simulados para pruebas.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$LogName,

        [Parameter()]
        [object]$InputObject
    )

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        $data = $InputObject
        if ($data -is [System.Collections.IDictionary]) {
            $data = [pscustomobject]$data
        }

        $simulatedName = $LogName
        if (-not [string]::IsNullOrWhiteSpace([string]$data.LogName)) {
            $simulatedName = [string]$data.LogName
        }

        $simulatedDays = $null
        if ($null -ne $data.DaysCovered) {
            $simulatedDays = [double]$data.DaysCovered
        } elseif ($null -ne $data.OldestEventTime) {
            $simulatedDays = ((Get-Date) - [datetime]$data.OldestEventTime).TotalDays
        }

        $simulatedEnabled = $true
        if ($null -ne $data.IsEnabled) {
            $simulatedEnabled = [bool]$data.IsEnabled
        }

        $simulatedSkipped = $false
        if ($null -ne $data.Skipped) {
            $simulatedSkipped = [bool]$data.Skipped
        }

        return [pscustomobject]@{
            LogName         = $simulatedName
            IsEnabled       = $simulatedEnabled
            MaxSizeMB       = [double]$data.MaxSizeMB
            CurrentSizeMB   = [double]$data.CurrentSizeMB
            EventCount      = [long]$data.EventCount
            LogMode         = [string]$data.LogMode
            OldestEventTime = $data.OldestEventTime
            DaysCovered     = $simulatedDays
            Skipped         = $simulatedSkipped
            Note            = [string]$data.Note
        }
    }

    try {
        $listLog = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    } catch {
        $failureNote = "No se pudo abrir el registro: $($_.Exception.Message)"
        if ($LogName -eq 'Security') {
            $failureNote = "Security requiere permisos de administrador; se omite. $($_.Exception.Message)"
        }
        return [pscustomobject]@{
            LogName         = $LogName
            IsEnabled       = $null
            MaxSizeMB       = 0
            CurrentSizeMB   = 0
            EventCount      = 0
            LogMode         = ''
            OldestEventTime = $null
            DaysCovered     = $null
            Skipped         = $true
            Note            = $failureNote
        }
    }

    $maximumBytes = [double]$listLog.MaximumSizeInBytes
    $currentBytes = [double]$listLog.FileSize
    $maxMB = 0
    $currentMB = 0
    if ($maximumBytes -gt 0) {
        $maxMB = [math]::Round($maximumBytes / 1MB, 2)
    }
    if ($currentBytes -gt 0) {
        $currentMB = [math]::Round($currentBytes / 1MB, 2)
    }

    $oldestTime = $null
    $note = ''
    $recordCount = [long]$listLog.RecordCount

    if ($recordCount -gt 0) {
        try {
            $oldestEvent = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop
            if ($null -ne $oldestEvent) {
                $oldestTime = $oldestEvent.TimeCreated
            }
        } catch {
            $note = "No se pudo leer el evento más antiguo: $($_.Exception.Message)"
            if ($LogName -eq 'Security') {
                return [pscustomobject]@{
                    LogName         = $LogName
                    IsEnabled       = [bool]$listLog.IsEnabled
                    MaxSizeMB       = $maxMB
                    CurrentSizeMB   = $currentMB
                    EventCount      = $recordCount
                    LogMode         = [string]$listLog.LogMode
                    OldestEventTime = $null
                    DaysCovered     = $null
                    Skipped         = $true
                    Note            = "Security requiere permisos de administrador; se omite. $($_.Exception.Message)"
                }
            }
        }
    }

    $daysCovered = $null
    if ($null -ne $oldestTime) {
        $daysCovered = ((Get-Date) - $oldestTime).TotalDays
    }

    return [pscustomobject]@{
        LogName         = [string]$listLog.LogName
        IsEnabled       = [bool]$listLog.IsEnabled
        MaxSizeMB       = $maxMB
        CurrentSizeMB   = $currentMB
        EventCount      = $recordCount
        LogMode         = [string]$listLog.LogMode
        OldestEventTime = $oldestTime
        DaysCovered     = $daysCovered
        Skipped         = $false
        Note            = $note
    }
}

function Get-LogStatus {
    <#
    .SYNOPSIS
        Evalúa la cobertura de un registro y devuelve un hallazgo.
    .DESCRIPTION
        Lógica pura: recibe un objeto con la información del registro (real o
        simulado) y devuelve un objeto con Comprobacion, Estado, Detalle, Valor,
        Recomendado y Solucion. No lee el sistema.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$MinDays = 7
    )

    process {
        $log = $InputObject
        if ($log -is [System.Collections.IDictionary]) {
            $log = [pscustomobject]$log
        }

        $logName = [string]$log.LogName
        if ([string]::IsNullOrWhiteSpace($logName)) {
            $logName = 'Desconocido'
        }

        if ($null -ne $log.Skipped -and [bool]$log.Skipped) {
            return [pscustomobject]@{
                Comprobacion = "Registro: $logName"
                Estado       = 'OK'
                Detalle      = "No se pudo leer el registro y se omite. $([string]$log.Note)".Trim()
                Valor        = 'Omitido'
                Recomendado  = ''
                Solucion     = ''
            }
        }

        $isSecurity = $logName -eq 'Security'
        $recommendedMB = 32
        if ($isSecurity) {
            $recommendedMB = 64
        }

        $isEnabled = $true
        if ($null -ne $log.IsEnabled) {
            $isEnabled = [bool]$log.IsEnabled
        }

        $logMode = [string]$log.LogMode
        $maxMB = 0
        if ($null -ne $log.MaxSizeMB) {
            $maxMB = [double]$log.MaxSizeMB
        }
        $currentMB = 0
        if ($null -ne $log.CurrentSizeMB) {
            $currentMB = [double]$log.CurrentSizeMB
        }

        $daysCovered = $null
        if ($null -ne $log.DaysCovered) {
            $daysCovered = [double]$log.DaysCovered
        } elseif ($null -ne $log.OldestEventTime) {
            $daysCovered = ((Get-Date) - [datetime]$log.OldestEventTime).TotalDays
        }

        $fillPercent = 0
        if ($maxMB -gt 0) {
            $fillPercent = [math]::Round(($currentMB / $maxMB) * 100)
        }
        $isFull = ($maxMB -gt 0 -and $currentMB -ge ($maxMB * 0.99))

        $estado = 'OK'
        $detalles = New-Object System.Collections.Generic.List[string]
        $recomendado = ''
        $solucion = ''

        if (-not $isEnabled) {
            $estado = 'Alta'
            [void]$detalles.Add('El registro está deshabilitado y no guarda eventos.')
            $recomendado = 'Registro habilitado'
        } elseif ($logMode -eq 'Retain' -and $isFull) {
            $estado = 'Alta'
            [void]$detalles.Add('El registro está lleno en modo Retain y dejará de registrar eventos nuevos.')
            $recomendado = 'Cambiar a modo Circular o AutoBackup y ampliar el tamaño'
        }

        if ($isEnabled -and $logMode -eq 'Circular' -and $maxMB -gt 0 -and $fillPercent -ge 90 -and $null -ne $daysCovered -and $daysCovered -lt $MinDays) {
            if ($estado -eq 'OK') {
                $estado = 'Aviso'
            }
            [void]$detalles.Add("El registro circular está lleno al $fillPercent % y pierde eventos antiguos.")
        }

        if ($isEnabled -and $maxMB -gt 0 -and $maxMB -lt $recommendedMB) {
            if ($estado -eq 'OK') {
                $estado = 'Aviso'
            }
            [void]$detalles.Add("Tamaño máximo de $maxMB MB, por debajo de los $recommendedMB MB recomendados.")
        }

        if ($isEnabled -and $null -ne $daysCovered -and $daysCovered -gt 0) {
            $durationText = Format-CoverageDuration -Days $daysCovered
            if ($daysCovered -lt $MinDays) {
                [void]$detalles.Add("Solo guarda $durationText de historia; se pide cobertura de $MinDays días.")
            } else {
                [void]$detalles.Add("Cubre $durationText de historia.")
            }
        } elseif ($isEnabled -and $null -eq $daysCovered) {
            if ($log.EventCount -eq 0) {
                [void]$detalles.Add('El registro no tiene eventos; no se puede calcular la cobertura.')
            } else {
                [void]$detalles.Add('No se pudo determinar la fecha del evento más antiguo; cobertura desconocida.')
            }
        }

        $suggestedMB = Get-SuggestedLogSize -CurrentSizeMB $currentMB -DaysCovered ([double]$daysCovered) -MinDays $MinDays -IsSecurity:$isSecurity
        if ($isEnabled -and $null -ne $daysCovered -and $daysCovered -gt 0 -and $currentMB -gt 0 -and
            ($currentMB * ($MinDays / [double]$daysCovered)) -gt $script:MaxSuggestedMB) {
            [void]$detalles.Add("Para cubrir $MinDays días haría falta más de $($script:MaxSuggestedMB) MB: algo está generando un volumen anormal de eventos; conviene revisar qué los produce antes de ampliar.")
        }
        if ([string]::IsNullOrWhiteSpace($recomendado)) {
            $recomendado = "$suggestedMB MB"
        }

        if ($logMode -eq 'Retain' -and $isFull) {
            $solucion = 'wevtutil sl "' + $logName + '" /rt:false /ms:' + ([int64]$suggestedMB * 1MB)
        } elseif (-not $isEnabled) {
            $solucion = 'wevtutil sl "' + $logName + '" /e:true ; wevtutil sl "' + $logName + '" /ms:' + ([int64]$suggestedMB * 1MB)
        } else {
            $solucion = 'wevtutil sl "' + $logName + '" /ms:' + ([int64]$suggestedMB * 1MB)
        }

        $eventCountText = [string]$log.EventCount
        $coverageText = 'desconocida'
        if ($null -ne $daysCovered) {
            $coverageText = (Format-CoverageDuration -Days $daysCovered)
        }

        $modeText = $logMode
        if ([string]::IsNullOrWhiteSpace($modeText)) {
            $modeText = 'desconocido'
        }

        $oldestText = 'desconocido'
        if ($null -ne $log.OldestEventTime) {
            $oldestText = ([datetime]$log.OldestEventTime).ToString('yyyy-MM-dd HH:mm')
        }

        $valor = "$currentMB MB de $maxMB MB ($fillPercent %), $eventCountText eventos, modo $modeText, más antiguo $oldestText, cobertura $coverageText"

        return [pscustomobject]@{
            Comprobacion = "Registro: $logName"
            Estado       = $estado
            Detalle      = ($detalles -join ' ')
            Valor        = $valor
            Recomendado  = $recomendado
            Solucion     = $solucion
        }
    }
}

function Test-PowerShellLogging {
    <#
    .SYNOPSIS
        Comprueba si ScriptBlockLogging está activado por directiva.
    .DESCRIPTION
        Lee HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging.
        Solo lee el registro; no crea ni modifica nada. Se puede pasar el valor ya
        leído con -EnableScriptBlockLogging para probar la lógica con datos simulados.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [object]$EnableScriptBlockLogging
    )

    $value = $null
    $note = ''
    if ($PSBoundParameters.ContainsKey('EnableScriptBlockLogging')) {
        $value = $EnableScriptBlockLogging
    } else {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        try {
            if (Test-Path -LiteralPath $policyPath) {
                $policy = Get-ItemProperty -LiteralPath $policyPath -Name 'EnableScriptBlockLogging' -ErrorAction Stop
                $value = $policy.EnableScriptBlockLogging
            } else {
                $value = 0
            }
        } catch {
            $note = "No se pudo leer la directiva: $($_.Exception.Message)"
        }
    }

    $isActive = $false
    if ($null -ne $value) {
        $text = [string]$value
        if ($text -eq '1' -or $text -eq 'True') {
            $isActive = $true
        }
    }

    if ($isActive) {
        return [pscustomobject]@{
            Comprobacion = 'Registro de bloques de PowerShell'
            Estado       = 'OK'
            Detalle      = 'ScriptBlockLogging está activado por directiva.'
            Valor        = 'Activado'
            Recomendado  = 'Mantener activado'
            Solucion     = ''
        }
    }

    $detail = 'ScriptBlockLogging no está activo; sin esto no se ve qué scripts se ejecutaron.'
    if (-not [string]::IsNullOrWhiteSpace($note)) {
        $detail = "$detail $note"
    }

    return [pscustomobject]@{
        Comprobacion = 'Registro de bloques de PowerShell'
        Estado       = 'Aviso'
        Detalle      = $detail
        Valor        = 'No activado'
        Recomendado  = 'EnableScriptBlockLogging = 1'
        Solucion     = 'New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force'
    }
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [object]$Text
    )

    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function New-EventLogSizeHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [object[]]$Findings = @(),

        [Parameter()]
        [string[]]$Notes = @(),

        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [datetime]$GeneratedAt = (Get-Date),

        [Parameter()]
        [int]$MinDays = 7
    )

    $okCount = @($Findings | Where-Object { $_.Estado -eq 'OK' }).Count
    $avisoCount = @($Findings | Where-Object { $_.Estado -eq 'Aviso' }).Count
    $altaCount = @($Findings | Where-Object { $_.Estado -eq 'Alta' }).Count

    $rows = New-Object System.Text.StringBuilder
    foreach ($finding in $Findings) {
        $cssClass = 'ok'
        if ($finding.Estado -eq 'Aviso') {
            $cssClass = 'aviso'
        } elseif ($finding.Estado -eq 'Alta') {
            $cssClass = 'alta'
        }

        [void]$rows.AppendLine('<tr class="' + $cssClass + '">')
        [void]$rows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $finding.Comprobacion) + '</td>')
        [void]$rows.AppendLine('<td><span class="pill ' + $cssClass + '">' + (ConvertTo-HtmlText -Text $finding.Estado) + '</span></td>')
        [void]$rows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $finding.Detalle) + '</td>')
        [void]$rows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $finding.Valor) + '</td>')
        [void]$rows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $finding.Recomendado) + '</td>')
        [void]$rows.AppendLine('<td class="command">' + (ConvertTo-HtmlText -Text $finding.Solucion) + '</td>')
        [void]$rows.AppendLine('</tr>')
    }

    $notesBlock = New-Object System.Text.StringBuilder
    if ($Notes.Count -gt 0) {
        [void]$notesBlock.AppendLine('<h2>Notas</h2>')
        [void]$notesBlock.AppendLine('<ul class="notes">')
        foreach ($item in $Notes) {
            [void]$notesBlock.AppendLine('<li>' + (ConvertTo-HtmlText -Text $item) + '</li>')
        }
        [void]$notesBlock.AppendLine('</ul>')
    } else {
        [void]$notesBlock.AppendLine('<p class="notes">Sin notas: todos los registros se pudieron leer.</p>')
    }

    $css = @'
:root {
    color-scheme: light dark;
    --bg: #f4f6f8;
    --panel: #ffffff;
    --text: #1a202c;
    --muted: #5b6572;
    --border: #d8dee6;
    --ok: #0f7b3f;
    --aviso: #b45309;
    --alta: #b91c1c;
    --ok-bg: #e7f6ec;
    --aviso-bg: #fef3c7;
    --alta-bg: #fee2e2;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #0f1419;
        --panel: #161c23;
        --text: #e6edf3;
        --muted: #9aa7b4;
        --border: #2b3541;
        --ok: #4ade80;
        --aviso: #fbbf24;
        --alta: #f87171;
        --ok-bg: #123324;
        --aviso-bg: #3a2a08;
        --alta-bg: #3b1414;
    }
}
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    font-size: 15px;
    line-height: 1.45;
}
main { max-width: 1200px; margin: 0 auto; }
h1 { margin: 0 0 4px; font-size: 24px; }
h2 { margin: 28px 0 8px; font-size: 18px; }
.meta { color: var(--muted); margin: 0 0 20px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 18px;
    min-width: 120px;
}
.card .num { display: block; font-size: 26px; font-weight: 700; }
.card.ok .num { color: var(--ok); }
.card.aviso .num { color: var(--aviso); }
.card.alta .num { color: var(--alta); }
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}
th, td {
    padding: 9px 11px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
}
th { background: rgba(127, 127, 127, 0.12); font-size: 13px; text-transform: uppercase; letter-spacing: 0.03em; }
tr.alta td { background: var(--alta-bg); }
tr.aviso td { background: var(--aviso-bg); }
.pill {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
}
.pill.ok { color: var(--ok); border: 1px solid var(--ok); }
.pill.aviso { color: var(--aviso); border: 1px solid var(--aviso); }
.pill.alta { color: var(--alta); border: 1px solid var(--alta); }
.command { font-family: Consolas, "Courier New", monospace; font-size: 13px; word-break: break-all; }
.notes { color: var(--muted); }
footer { margin-top: 28px; color: var(--muted); font-size: 13px; }
'@

    $template = @'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Registros de eventos - __COMPUTER__</title>
<style>
__CSS__
</style>
</head>
<body>
<main>
<h1>Revisión de tamaño y cobertura de los registros de eventos</h1>
<p class="meta">Equipo: <strong>__COMPUTER__</strong> &middot; Fecha: __DATE__ &middot; Cobertura mínima deseada: __MINDAYS__ días</p>
<div class="cards">
<div class="card ok"><span class="num">__OK__</span><span>OK</span></div>
<div class="card aviso"><span class="num">__AVISO__</span><span>Aviso</span></div>
<div class="card alta"><span class="num">__ALTA__</span><span>Alta</span></div>
</div>
<table>
<thead>
<tr><th>Comprobación</th><th>Estado</th><th>Detalle</th><th>Valor</th><th>Recomendado</th><th>Solución (solo ejemplo)</th></tr>
</thead>
<tbody>
__ROWS__
</tbody>
</table>
__NOTES__
<footer>Informe generado automáticamente. Herramienta de solo lectura: no modifica la configuración del equipo. Los comandos de la columna Solución son ejemplos y no se han ejecutado.</footer>
</main>
</body>
</html>
'@

    $html = $template.Replace('__CSS__', $css)
    $html = $html.Replace('__COMPUTER__', (ConvertTo-HtmlText -Text $ComputerName))
    $html = $html.Replace('__DATE__', (ConvertTo-HtmlText -Text $GeneratedAt.ToString('yyyy-MM-dd HH:mm')))
    $html = $html.Replace('__MINDAYS__', (ConvertTo-HtmlText -Text $MinDays))
    $html = $html.Replace('__OK__', (ConvertTo-HtmlText -Text $okCount))
    $html = $html.Replace('__AVISO__', (ConvertTo-HtmlText -Text $avisoCount))
    $html = $html.Replace('__ALTA__', (ConvertTo-HtmlText -Text $altaCount))
    $html = $html.Replace('__ROWS__', $rows.ToString())
    $html = $html.Replace('__NOTES__', $notesBlock.ToString())

    return $html
}

function Export-EventLogSizeReport {
    <#
    .SYNOPSIS
        Escribe el informe JSON y el HTML autónomo.
    .DESCRIPTION
        Crea <OutputPath>\event-log-size.json y <OutputPath>\report.html.
        El HTML lleva el CSS en línea, no usa JavaScript externo, admite modo
        oscuro con prefers-color-scheme y escapa todos los textos dinámicos.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string[]]$Notes = @(),

        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [datetime]$GeneratedAt = (Get-Date),

        [Parameter()]
        [int]$MinDays = 7,

        [Parameter()]
        [string]$Name = 'event-log-size'
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $resolvedDir = (Resolve-Path -LiteralPath $OutputPath).ProviderPath

    $okCount = @($Findings | Where-Object { $_.Estado -eq 'OK' }).Count
    $avisoCount = @($Findings | Where-Object { $_.Estado -eq 'Aviso' }).Count
    $altaCount = @($Findings | Where-Object { $_.Estado -eq 'Alta' }).Count

    $payload = [pscustomobject]@{
        Equipo       = $ComputerName
        Fecha        = $GeneratedAt.ToString('o')
        DiasMinimos  = $MinDays
        Resumen      = [pscustomobject]@{
            OK    = $okCount
            Aviso = $avisoCount
            Alta  = $altaCount
        }
        Hallazgos    = @($Findings)
        Notas        = @($Notes)
    }

    $jsonPath = Join-Path -Path $resolvedDir -ChildPath "$Name.json"
    $htmlPath = Join-Path -Path $resolvedDir -ChildPath 'report.html'

    $json = $payload | ConvertTo-Json -Depth 8
    $html = New-EventLogSizeHtml -Findings $Findings -Notes $Notes -ComputerName $ComputerName -GeneratedAt $GeneratedAt -MinDays $MinDays

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($jsonPath, $json, $utf8NoBom)
    [System.IO.File]::WriteAllText($htmlPath, $html, $utf8NoBom)

    return [pscustomobject]@{
        Json = $jsonPath
        Html = $htmlPath
    }
}

Export-ModuleMember -Function Get-EventLogCoverage, Get-LogStatus, Get-SuggestedLogSize, Test-PowerShellLogging, Export-EventLogSizeReport
