<#
.SYNOPSIS
    1C server cache cleanup (registry-driven).

.DESCRIPTION
    Version 3.1.5
    - Stable localization formatting (no runtime -f errors)
    - Registry is the single source of truth
    - Stop Server + Agent -> clean cache -> start Agent + Server
    - ASCII-only script body

.VERSION
    3.1.5
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [int]$ServiceStopTimeout = 120,
    [string]$SrvInfoPath,
    [ValidateSet("en-US", "ru-RU")]
    [string]$Language,
    [switch]$Diagnostic,
    [switch]$Force,
    [switch]$NoServiceRestart
)

# =========================
# Global state
# =========================
$Script:Config = $null
$Script:Localization = $null
$Script:LanguageEffective = "en-US"

# =========================
# Localization helpers
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

function Format-Loc {
    param(
        [string]$Template,
        [object[]]$Args
    )

    if ([string]::IsNullOrWhiteSpace($Template)) {
        return ""
    }

    if (-not $Args -or $Args.Count -eq 0) {
        return $Template
    }

    try {
        return $Template -f $Args
    } catch {
        # Gradually reduce argument list
        for ($i = $Args.Count - 1; $i -ge 0; $i--) {
            try {
                return $Template -f $Args[0..$i]
            } catch {
                continue
            }
        }
        # Absolute fallback
        return $Template
    }
}

function Get-1CLocalization {
    param([string]$Language)

    $base = Join-Path $PSScriptRoot "Localization"
    $file = Join-Path $base ($Language + ".psd1")

    if (Test-Path $file) {
        return Import-LocalizedData -BaseDirectory $base -FileName ($Language + ".psd1")
    }
    return Import-LocalizedData -BaseDirectory $base -FileName "en-US.psd1"
}

# =========================
# Settings
# =========================
function Load-1CSettings {
    $cfgPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $cfgPath) {
        $Script:Config = (Get-Content $cfgPath -Raw -Encoding UTF8) | ConvertFrom-Json
    } else {
        $Script:Config = [PSCustomObject]@{
            version  = "3.1.6"
            defaults = [PSCustomObject]@{
                language = "auto"
                serviceStopTimeout = 120
            }
            paths    = [PSCustomObject]@{
                defaultSrvInfo = "C:\Program Files\1cv8\srvinfo"
                logDirectory   = "C:\Scripts\Logs\1C_Maintenance"
            }
            safety   = [PSCustomObject]@{
                checkActiveSessions = $true
            }
        }
    }

    if ($Language) {
        $Script:LanguageEffective = $Language
    } else {
        $l = $Script:Config.defaults.language
        $Script:LanguageEffective = if ($l -eq "auto") { (Get-Culture).Name } else { $l }
    }

    if ($Script:LanguageEffective -notin @("en-US","ru-RU")) {
        $Script:LanguageEffective = "en-US"
    }

    $Script:Localization = Get-1CLocalization -Language $Script:LanguageEffective
}

# =========================
# Logging
# =========================
function Initialize-Logging {
    $dir = $Script:Config.paths.logDirectory
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    return (Join-Path $dir ("1CCacheCleaner_{0}.log" -f $ts))
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level,
        [string]$LogFile
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $ts, $Level, $Message
    Write-Host $line
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# =========================
# Registry discovery
# =========================
function Get-1CRagentServicesFromRegistry {
    $base = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $items = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
    $result = @()

    foreach ($i in $items) {
        $p = Get-ItemProperty -Path $i.PSPath -ErrorAction SilentlyContinue
        if (-not $p.ImagePath) { continue }
        if ($p.ImagePath -notmatch '(?i)ragent\.exe') { continue }

        $srvInfo = $null
        if ($p.ImagePath -match '(?i)-d\s+"([^"]+)"') {
            $srvInfo = $Matches[1]
        }

        $role = if ($p.ImagePath -match '(?i)-server') {
            "Server"
        } else {
            "Agent"
        }

        $result += [PSCustomObject]@{
            ServiceName = $i.PSChildName
            DisplayName = $p.DisplayName
            Role        = $role
            SrvInfoPath = $srvInfo
        }
    }
    return $result
}

# =========================
# Cache cleanup
# =========================
function Clear-1CCache {
    param(
        [string]$Path,
        [string]$LogFile
    )

    $tpl = Get-Loc Messages CleanupStarting "Starting cache cleanup: {0}"
    Write-Log (Format-Loc $tpl @($Path)) INFO $LogFile

    $dirs = Get-ChildItem $Path -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    foreach ($d in $dirs) {
        $files = Get-ChildItem $d.FullName -File -Recurse -ErrorAction SilentlyContinue
        if ($files.Count -gt 0) {
            $files | Remove-Item -Force -ErrorAction SilentlyContinue
            $tpl = Get-Loc Messages CacheDirCleaned "Cleaned: {0} ({1} files)"
            Write-Log (Format-Loc $tpl @($d.FullName,$files.Count)) INFO $LogFile
        }
    }
}

# =========================
# Main
# =========================
function Main {
    Load-1CSettings
    $log = Initialize-Logging

    $tpl = Get-Loc Messages ScriptStarted "Cache cleanup started (version {0})."
    Write-Log (Format-Loc $tpl @($Script:Config.version)) INFO $log

    $services = Get-1CRagentServicesFromRegistry
    if (-not $services) {
        Write-Log "1C services not found in registry. Nothing to do." WARNING $log
        return
    }

    $srvPath = if ($SrvInfoPath) { $SrvInfoPath } else { $services[0].SrvInfoPath }

    foreach ($s in $services | Where-Object Role -eq "Server") {
        Stop-Service -Name $s.ServiceName -Force
    }
    foreach ($s in $services | Where-Object Role -eq "Agent") {
        Stop-Service -Name $s.ServiceName -Force
    }

    Clear-1CCache -Path $srvPath -LogFile $log

    foreach ($s in $services | Where-Object Role -eq "Agent") {
        Start-Service -Name $s.ServiceName
    }
    foreach ($s in $services | Where-Object Role -eq "Server") {
        Start-Service -Name $s.ServiceName
    }

    Write-Log "Cache cleanup completed successfully." SUCCESS $log
}

Main
