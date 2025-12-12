<#
.SYNOPSIS
    1C server cache cleanup utility.

.DESCRIPTION
    Version 3.1.3
    - Correct localization formatting
    - Robust service discovery by DisplayName (exact + wildcard)
    - Native PowerShell -WhatIf / -Confirm
    - ASCII-only script body

.VERSION
    3.1.3
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param (
    [int]$ServiceStopTimeout = 120,
    [string]$SrvInfoPath,
    [ValidateSet("en-US", "ru-RU")]
    [string]$Language,
    [switch]$Diagnostic,
    [switch]$Force,
    [switch]$NoServiceRestart
)

# =========================
# GLOBAL STATE
# =========================

$Script:Config = $null
$Script:Localization = $null
$Script:LanguageEffective = "en-US"

# =========================
# LOCALIZATION HELPERS
# =========================

function Get-Loc {
    param(
        [string]$Section,
        [string]$Key,
        [string]$Fallback
    )

    try {
        $v = $Script:Localization.$Section.$Key
        if ([string]::IsNullOrWhiteSpace($v)) { return $Fallback }
        return $v
    } catch {
        return $Fallback
    }
}

function Get-1CLocalization {
    param([string]$Language)

    $base = Join-Path $PSScriptRoot "Localization"
    $file = Join-Path $base "$Language.psd1"

    if (Test-Path $file) {
        return Import-LocalizedData -BaseDirectory $base -FileName "$Language.psd1"
    }

    return Import-LocalizedData -BaseDirectory $base -FileName "en-US.psd1"
}

# =========================
# SETTINGS
# =========================

function Load-1CSettings {
    $cfgPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $cfgPath) {
        $Script:Config = (Get-Content $cfgPath -Raw -Encoding UTF8) | ConvertFrom-Json
    } else {
        $Script:Config = @{
            version = "3.1.3"
            defaults = @{
                language = "auto"
                serviceStopTimeout = 120
            }
            paths = @{
                defaultSrvInfo = "C:\Program Files\1cv8\srvinfo"
                logDirectory   = "C:\Scripts\Logs\1C_Maintenance"
            }
            safety = @{
                checkActiveSessions = $true
                requireConfirmation = $false
            }
            logging = @{
                level = "INFO"
                enableEventLog = $true
            }
        }
    }

    if ($Language) {
        $Script:LanguageEffective = $Language
    } else {
        $l = $Script:Config.defaults.language
        if ($l -eq "auto") {
            $Script:LanguageEffective = (Get-Culture).Name
        } else {
            $Script:LanguageEffective = $l
        }
    }

    if ($Script:LanguageEffective -notin @("en-US","ru-RU")) {
        $Script:LanguageEffective = "en-US"
    }

    $Script:Localization = Get-1CLocalization -Language $Script:LanguageEffective
}

# =========================
# LOGGING
# =========================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level,
        [string]$LogFile
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $ts, $Level, $Message
    Write-Host $line

    if ($LogFile) {
        $line | Out-File -Append -FilePath $LogFile -Encoding UTF8
    }
}

function Init-Log {
    $dir = $Script:Config.paths.logDirectory
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }

    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    return (Join-Path $dir "1CCacheCleaner_$ts.log")
}

# =========================
# SERVICE RESOLUTION
# =========================

function Resolve-1CService {
    param([string]$DisplayName)

    if (-not $DisplayName) { return $null }

    $svc = Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($svc) { return $svc | Select-Object -First 1 }

    $svc = Get-Service -DisplayName ($DisplayName + "*") -ErrorAction SilentlyContinue
    if ($svc) { return $svc | Select-Object -First 1 }

    return $null
}

# =========================
# CACHE CLEANUP
# =========================

function Clear-1CCache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$LogFile
    )

    $tpl = Get-Loc Messages CleanupStarting "Starting cache cleanup: {0}"
    Write-Log ($tpl -f $Path) INFO $LogFile

    $dirs = Get-ChildItem $Path -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    if (-not $dirs) {
        Write-Log (Get-Loc Messages CacheDirsNotFound "No cache directories found.") WARNING $LogFile
        return
    }

    foreach ($d in $dirs) {
        $files = Get-ChildItem $d.FullName -File -Recurse -ErrorAction SilentlyContinue
        if ($files.Count -eq 0) { continue }

        if ($PSCmdlet.ShouldProcess($d.FullName, "Remove cache files")) {
            $files | Remove-Item -Force -ErrorAction SilentlyContinue
            $tpl = Get-Loc Messages CacheDirCleaned "Cleaned {0} ({1} files)"
            Write-Log ($tpl -f $d.FullName, $files.Count) INFO $LogFile
        } else {
            $tpl = Get-Loc Messages CacheDirFoundWhatIf "[WhatIf] Found {0} ({1} files)"
            Write-Log ($tpl -f $d.FullName, $files.Count) INFO $LogFile
        }
    }
}

# =========================
# MAIN
# =========================

function Main {
    Load-1CSettings
    $log = Init-Log

    $tpl = Get-Loc Messages ScriptStarted "Cache cleanup started. Version {0}"
    Write-Log ($tpl -f $Script:Config.version) INFO $log

    $srvPath = if ($SrvInfoPath) {
        $SrvInfoPath
    } else {
        $Script:Config.paths.defaultSrvInfo
    }

    $agentName = Get-Loc ServiceNames Agent "1C:Enterprise 8.3 Server Agent"
    $serverName = Get-Loc ServiceNames Server "1C:Enterprise 8.3 Server"

    $services = @($agentName, $serverName)

    if (-not $NoServiceRestart) {
        foreach ($dn in $services) {
            $svc = Resolve-1CService $dn
            if (-not $svc) {
                $tpl = Get-Loc Messages ServiceNotFound "Service not found: {0}"
                Write-Log ($tpl -f $dn) WARNING $log
                continue
            }

            if ($PSCmdlet.ShouldProcess($svc.DisplayName, "Stop service")) {
                Stop-Service $svc.Name -Force
                $tpl = Get-Loc Messages ServiceStopped "Service stopped: {0}"
                Write-Log ($tpl -f $svc.DisplayName) INFO $log
            }
        }
    }

    Clear-1CCache -Path $srvPath -LogFile $log

    if (-not $NoServiceRestart) {
        foreach ($dn in $services) {
            $svc = Resolve-1CService $dn
            if ($svc -and $PSCmdlet.ShouldProcess($svc.DisplayName, "Start service")) {
                Start-Service $svc.Name
                $tpl = Get-Loc Messages ServiceStarted "Service started: {0}"
                Write-Log ($tpl -f $svc.DisplayName) INFO $log
            }
        }
    }

    Write-Log (Get-Loc Messages Completion "Cache cleanup completed.") SUCCESS $log

    if ($WhatIfPreference) {
        Write-Log (Get-Loc Messages DryRunNotice1 "This was a dry run.") INFO $log
    }
}

Main
