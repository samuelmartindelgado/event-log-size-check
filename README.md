# event-log-size-check

[![CI](https://github.com/samuelmartindelgado/event-log-size-check/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelmartindelgado/event-log-size-check/actions/workflows/ci.yml)

Comprobación de solo lectura para Windows que revisa si los registros de eventos importantes guardan historia suficiente.

## Por qué importa

Windows crea muchos registros con un tamaño máximo de 20 MB y modo circular. En un equipo con actividad normal esos 20 MB se llenan en pocas horas: cuando hay un incidente, un reinicio inesperado o una caída, los eventos que explican lo ocurrido ya se han sobrescrito. Este script mide cuánta historia conserva cada registro y avisa antes de que falte información, sin cambiar nada del equipo.

## Qué revisa

| Comprobación | Detalle |
| --- | --- |
| Tamaño máximo | Límite configurado para el registro, en MB |
| Tamaño actual | Espacio ocupado y porcentaje de llenado |
| Número de eventos | Eventos almacenados en este momento |
| Modo de sobrescritura | `Circular`, `AutoBackup` o `Retain` |
| Evento más antiguo | Fecha del evento más viejo disponible |
| Días cubiertos | Historia que conserva el registro |
| Estado | `OK`, `Aviso` o `Alta` según las reglas siguientes |
| ScriptBlockLogging | Directiva `EnableScriptBlockLogging` de PowerShell |

Reglas de estado:

- **Alta**: el registro está deshabilitado (`IsEnabled = false`).
- **Alta**: el registro está en modo `Retain` y lleno; dejará de registrar eventos nuevos.
- **Aviso**: registro circular lleno al 90 % o más y con menos días de los deseados.
- **Aviso**: tamaño máximo menor de 64 MB en `Security` o menor de 32 MB en el resto.
- **Aviso**: `ScriptBlockLogging` no está activado.
- **OK**: el resto de casos.

Si la cobertura es menor de la deseada, el detalle indica cuántos días u horas de historia se conservan. El tamaño sugerido se calcula como `tamaño actual × (días deseados / días cubiertos)`, redondeado hacia arriba a múltiplos de 64 MB y con el mínimo recomendado.

## Requisitos

- Windows con PowerShell 5.1 o PowerShell 7.
- Sin módulos externos para ejecutar el script.
- No requiere administrador, aunque `Security` solo se puede leer con permisos elevados. Si no se puede abrir, se omite con una nota.
- Pester 5.5 o superior solo para ejecutar las pruebas.

## Uso

```powershell
# Revisión con la cobertura mínima por defecto (7 días)
./Test-EventLogSize.ps1

# Exigir 14 días de historia y guardar los informes
./Test-EventLogSize.ps1 -MinDays 14 -OutputPath ./salida

# Revisar solo registros concretos
./Test-EventLogSize.ps1 -LogName 'System', 'Application'
```

Parámetros:

| Parámetro | Valor por defecto | Descripción |
| --- | --- | --- |
| `-MinDays` | `7` | Días mínimos de historia que se desean conservar |
| `-LogName` | `Security`, `System`, `Application`, `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-Windows Defender/Operational` | Registros que se revisan |
| `-OutputPath` | vacío | Carpeta donde se escriben `event-log-size.json` y `report.html` |

Códigos de salida: `0` si todo está OK, `1` si hay algún aviso y `2` si hay alguna alta.

## Ejemplo de salida

Datos ficticios del equipo `PC-DEMO`:

```text
Revisión de registros de eventos - PC-DEMO - 2026-01-15 09:30
Cobertura mínima deseada: 7 días

[Aviso] Registro: System
       El registro circular está lleno al 100 % y pierde eventos antiguos. Tamaño máximo de 20 MB, por debajo de los 32 MB recomendados. Solo guarda 9 horas de historia; se pide cobertura de 7 días.
       Recomendado: 384 MB
       Solución (ejemplo, no ejecutada): wevtutil sl "System" /ms:402653184

[Alta] Registro: Microsoft-Windows-TaskScheduler/Operational
       El registro está deshabilitado y no guarda eventos.
       Recomendado: Registro habilitado
       Solución (ejemplo, no ejecutada): wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true ; wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:67108864

[OK] Registro: Application
       Cubre 21,4 días de historia.
       Recomendado: 64 MB
       Solución (ejemplo, no ejecutada): wevtutil sl "Application" /ms:67108864

[Aviso] Registro de bloques de PowerShell
       ScriptBlockLogging no está activo; sin esto no se ve qué scripts se ejecutaron.
       Recomendado: EnableScriptBlockLogging = 1
       Solución (ejemplo, no ejecutada): New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force

Notas:
  - Security: Security requiere permisos de administrador; se omite. ...

Resumen: 5 OK, 2 avisos, 1 alta
Solo lectura: no se ha modificado ningún registro ni directiva.
```

Con `-OutputPath ./salida` se generan además:

- `salida/event-log-size.json`: datos del equipo, resumen y hallazgos.
- `salida/report.html`: informe autónomo con CSS en línea, sin JavaScript externo, modo oscuro automático y filas en rojo o ámbar.

## Cómo corregir cada hallazgo

Los comandos siguientes son ejemplos. Este script **no los ejecuta**; revíselos y ejecútelos manualmente con una consola elevada si corresponde.

### Registro deshabilitado

```powershell
wevtutil sl "NombreDelRegistro" /e:true
```

### Registro Retain lleno

Cambie a modo circular (o `AutoBackup`) y amplíe el tamaño. Con `/rt:false` el registro vuelve a sobrescribir los eventos más antiguos:

```powershell
wevtutil sl "NombreDelRegistro" /rt:false /ms:134217728
```

### Registro circular lleno con poca historia

Aumente el tamaño máximo. El valor se indica en bytes (`MB × 1048576`):

```powershell
wevtutil sl "System" /ms:402653184
```

Compruebe el resultado en Visor de eventos → Propiedades del registro, o con:

```powershell
Get-WinEvent -ListLog System | Select-Object LogName, MaximumSizeInBytes, FileSize, LogMode
```

### Tamaño máximo pequeño

Aplique el tamaño sugerido por el informe, como mínimo 64 MB en `Security` y 32 MB en los demás registros. También puede ajustarlo desde la interfaz del Visor de eventos.

### ScriptBlockLogging desactivado

Active la directiva por equipo:

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
```

En un dominio, lo habitual es configurarla mediante GPO: **Configuración del equipo → Plantillas administrativas → Componentes de Windows → Windows PowerShell → Activar el registro de bloques de script de PowerShell**.

## Solo lectura

El script y el módulo únicamente leen el sistema:

- `Get-WinEvent -ListLog` y `Get-WinEvent -MaxEvents 1 -Oldest` para los registros.
- `Get-ItemProperty` para la directiva de PowerShell.
- Escritura limitada a la carpeta indicada con `-OutputPath`.

No cambia tamaños, modos, estados ni directivas. Los comandos de la columna Solución son texto informativo.

## Pruebas

```powershell
pwsh -NoProfile -Command "Invoke-Pester ./tests -Output Detailed"
powershell -NoProfile -Command "Invoke-Pester ./tests"
```

Las pruebas cubren la lógica de decisión con objetos simulados (registro deshabilitado, `Retain` lleno, circular lleno con 0,5 días, registro sano), el cálculo del tamaño sugerido, el escapado del HTML y que la lectura real no lance excepciones.

## Licencia

MIT. Consulte [LICENSE](LICENSE).

---

## English summary

Read-only Windows health check that verifies whether important event logs keep enough history. Many logs default to 20 MB in circular mode and overwrite their contents within hours, so evidence is gone when an incident happens. The script reports maximum and current size, event count, retention mode, oldest event and days covered, then returns `OK`, `Warning` or `High` findings with a suggested size and an example `wevtutil sl "<log>" /ms:<bytes>` command that is never executed. It also checks PowerShell ScriptBlockLogging. It works on Windows PowerShell 5.1 and PowerShell 7, runs without admin where possible, skips unreadable logs with a note, and can write a JSON file plus a self-contained HTML report. Exit codes: 0 all OK, 1 any warning, 2 any high finding. MIT licensed.
