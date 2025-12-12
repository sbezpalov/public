<#
.SYNOPSIS
    1C server cache cleanup (registry-driven).

.DESCRIPTION
    Version 3.1.4
    - Discovers 1C services from registry (Services\*\ImagePath contains ragent.exe)
    - Determines roles by ragent.exe arguments:
        -agent  -> Agent
        -server -> Server (if present)
      Other ragent-based services are ignored by default for safety.
    - Stop -> Clear cache -> Start
    - Native -WhatIf / -Confirm via ShouldProcess
    - ASCII-only script; UI text should live in localization files

.VERSION
    3.1.4
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

# -------------------------
# Global state
# -------------------------
$Script:Config = $null
$Script:Localization = $null
$Script:LanguageEffective = "en-US"

# -------------------------
# Localization helpers
# -------------------------
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
    $file = Join-Path $base ($Language + ".psd1")

    if (Test-Path $file) {
        return Import-LocalizedData -BaseDirectory $base -FileName ($Language + ".psd1")
    }
    return Import-LocalizedData -BaseDirectory $base -FileName "en-US.psd1"
}

# -------------------------
# Settings
# -------------------------
function Load-1CSettings {
    $cfgPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $cfgPath) {
        try {
            $Script:Config = (Get-Content $cfgPath -Raw -Encoding UTF8) | ConvertFrom-Json
        } catch {
            throw ("Failed to read settings.json: {0}" -f $_.Exception.Message)
        }
    } else {
        $Script:Config = [PSCustomObject]@{
            version  = "3.1.4"
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
                requireConfirmation = $false
            }
            logging  = [PSCustomObject]@{
                level = "INFO"
            }
        }
    }

    if ($Language) {
        $Script:LanguageEffective = $Language
    } else {
        $l = $Script:Config.defaults.language
        if ([string]::IsNullOrWhiteSpace($l) -or $l -eq "auto") {
            $Script:LanguageEffective = (Get-Culture).Name
        } else {
            $Script:LanguageEffective = $l
        }
    }

    if ($Script:LanguageEffective -notin @("en-US", "ru-RU")) {
        $Script:LanguageEffective = "en-US"
    }

    $Script:Localization = Get-1CLocalization -Language $Script:LanguageEffective
}

# -------------------------
# Logging
# -------------------------
function Initialize-Logging {
    $dir = $Script:Config.paths.logDirectory
    if ([string]::IsNullOrWhiteSpace($dir)) {
        $dir = "C:\Scripts\Logs\1C_Maintenance"
    }

    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    return (Join-Path $dir ("1CCacheCleaner_{0}.log" -f $ts))
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("DEBUG","INFO","WARNING","ERROR","SUCCESS")]
        [string]$Level = "INFO",
        [string]$LogFile
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $ts, $Level, $Message
    Write-Host $line

    if ($LogFile) {
        $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}

# -------------------------
# Admin check
# -------------------------
function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $msg = Get-Loc Messages AdminRequired "Script must be run as Administrator."
        throw $msg
    }
}

# -------------------------
# Registry discovery for 1C services
# -------------------------

function Parse-RagentArgs {
    param([string]$ImagePath)

    # Returns hashtable of switches like { agent = $true; server = $true; d = "path" }
    $h = @{}

    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $h }

    # Normalize
    $s = $ImagePath

    # Capture -d "path with spaces" or -d path
    if ($s -match '(?i)(?:\s|^)-d\s+"([^"]+)"') {
        $h["d"] = $Matches[1]
    } elseif ($s -match '(?i)(?:\s|^)-d\s+([^\s]+)') {
        $h["d"] = $Matches[1]
    }

    if ($s -match '(?i)(?:\s|^)-agent(?:\s|$)')  { $h["agent"]  = $true }
    if ($s -match '(?i)(?:\s|^)-server(?:\s|$)') { $h["server"] = $true }

    return $h
}

function Get-1CRagentServicesFromRegistry {
    # Returns list of { ServiceName, DisplayName, ImagePath, Role, SrvInfoPath }
    $base = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $items = Get-ChildItem -Path $base -ErrorAction SilentlyContinue

    $result = @()

    foreach ($i in $items) {
        try {
            $p = Get-ItemProperty -Path $i.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { continue }
            if (-not $p.ImagePath) { continue }

            $img = [string]$p.ImagePath
            if ($img -notmatch '(?i)ragent\.exe') { continue }

            $args = Parse-RagentArgs -ImagePath $img

            $role = "OtherRagent"
            if ($args.ContainsKey("agent"))  { $role = "Agent" }
            if ($args.ContainsKey("server")) { $role = "Server" }

            $srvInfo = $null
            if ($args.ContainsKey("d")) { $srvInfo = $args["d"] }

            $result += [PSCustomObject]@{
                ServiceName = $i.PSChildName
                DisplayName = $p.DisplayName
                ImagePath   = $img
                Role        = $role
                SrvInfoPath = $srvInfo
            }
        } catch {
            continue
        }
    }

    return $result
}

function Select-1CServicesForMaintenance {
    param([object[]]$AllServices)

    # Safety-first:
    # - Prefer explicit Server and Agent roles
    # - If Server role not found, we still stop Agent (common scenario)
    # - Do not stop OtherRagent services by default (avoid collateral impact)

    $agent = $AllServices | Where-Object { $_.Role -eq "Agent" }  | Select-Object -First 1
    $server = $AllServices | Where-Object { $_.Role -eq "Server" } | Select-Object -First 1

    # Some installs may not mark server role; in that case, server is null.
    return [PSCustomObject]@{
        Agent  = $agent
        Server = $server
    }
}

# -------------------------
# Safety
# -------------------------
function Test-Safety {
    param(
        [switch]$Force,
        [string]$LogFile
    )

    if ($Force) {
        $tpl = Get-Loc Messages ForceSkipsSafety "Force is set: safety checks are skipped."
        Write-Log -Message $tpl -Level "WARNING" -LogFile $LogFile
        return $true
    }

    if ($Script:Config.safety -and ($Script:Config.safety.checkActiveSessions -eq $false)) {
        $tpl = Get-Loc Messages ActiveSessionCheckDisabled "Active session check is disabled in settings.json."
        Write-Log -Message $tpl -Level "WARNING" -LogFile $LogFile
        return $true
    }

    # Minimal check: active 1C processes
    $p = Get-Process -Name "1cv8","1cv8c","1cv8s" -ErrorAction SilentlyContinue
    if ($p) {
        $tpl = Get-Loc Messages SafetyCheckFailed "Safety check failed: active 1C processes detected."
        Write-Log -Message $tpl -Level "ERROR" -LogFile $LogFile
        return $false
    }

    $tpl = Get-Loc Messages SafetyCheckPassed "Safety check passed."
    Write-Log -Message $tpl -Level "INFO" -LogFile $LogFile
    return $true
}

# -------------------------
# Service control (by ServiceName)
# -------------------------
function Stop-ServiceSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object]$SvcObj,
        [int]$Timeout,
        [string]$LogFile
    )

    if (-not $SvcObj) { return }

    $name = $SvcObj.ServiceName
    $caption = if ([string]::IsNullOrWhiteSpace($SvcObj.DisplayName)) { $name } else { $SvcObj.DisplayName }

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        $tpl = Get-Loc Messages ServiceNotFound "Service not found: {0}"
        Write-Log -Message ($tpl -f $caption) -Level "WARNING" -LogFile $LogFile
        return
    }

    if ($svc.Status -eq "Stopped") {
        $tpl = Get-Loc Messages ServiceAlreadyStopped "Service already stopped: {0}"
        Write-Log -Message ($tpl -f $caption) -Level "INFO" -LogFile $LogFile
        return
    }

    if ($PSCmdlet.ShouldProcess($caption, "Stop service")) {
        try {
            $tpl = Get-Loc Messages ServiceStopping "Stopping service: {0}"
            Write-Log -Message ($tpl -f $caption) -Level "INFO" -LogFile $LogFile

            Stop-Service -Name $name -Force -ErrorAction Stop
            $svc.WaitForStatus("Stopped", (New-TimeSpan -Seconds $Timeout))

            $tpl = Get-Loc Messages ServiceStopped "Service stopped: {0}"
            Write-Log -Message ($tpl -f $caption) -Level "SUCCESS" -LogFile $LogFile
        } catch {
            $tpl = Get-Loc Messages ServiceStopFailed "Failed to stop service {0}: {1}"
            Write-Log -Message ($tpl -f $caption, $_.Exception.Message) -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

function Start-ServiceSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object]$SvcObj,
        [string]$LogFile
    )

    if (-not $SvcObj) { return }

    $name = $SvcObj.ServiceName
    $caption = if ([string]::IsNullOrWhiteSpace($SvcObj.DisplayName)) { $name } else { $SvcObj.DisplayName }

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        $tpl = Get-Loc Messages ServiceNotFound "Service not found: {0}"
        Write-Log -Message ($tpl -f $caption) -Level "WARNING" -LogFile $LogFile
        return
    }

    if ($svc.Status -eq "Running") {
        # Optional noise reduction; not critical
        return
    }

    if ($PSCmdlet.ShouldProcess($caption, "Start service")) {
        try {
            $tpl = Get-Loc Messages ServiceStarting "Starting service: {0}"
            Write-Log -Message ($tpl -f $caption) -Level "INFO" -LogFile $LogFile

            Start-Service -Name $name -ErrorAction Stop

            $tpl = Get-Loc Messages ServiceStarted "Service started: {0}"
            Write-Log -Message ($tpl -f $caption) -Level "SUCCESS" -LogFile $LogFile
        } catch {
            $tpl = Get-Loc Messages ServiceStartFailed "Failed to start service {0}: {1}"
            Write-Log -Message ($tpl -f $caption, $_.Exception.Message) -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

# -------------------------
# Cache cleanup
# -------------------------
function Clear-1CCache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$LogFile
    )

    $tpl = Get-Loc Messages CleanupStarting "Starting cache cleanup: {0}"
    Write-Log -Message ($tpl -f $Path) -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $Path)) {
        $tpl = Get-Loc Messages PathNotFound "Path not found: {0}"
        Write-Log -Message ($tpl -f $Path) -Level "ERROR" -LogFile $LogFile
        throw ($tpl -f $Path)
    }

    $dirs = Get-ChildItem -Path $Path -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    if (-not $dirs) {
        $tpl = Get-Loc Messages CacheDirsNotFound "No cache directories found under {0}"
        Write-Log -Message ($tpl -f $Path) -Level "WARNING" -LogFile $LogFile
        return
    }

    $totalDirs = 0
    $totalFiles = 0

    foreach ($d in $dirs) {
        $files = Get-ChildItem -Path $d.FullName -File -Recurse -ErrorAction SilentlyContinue
        $cnt = $files.Count
        if ($cnt -le 0) { continue }

        if ($PSCmdlet.ShouldProcess($d.FullName, ("Remove {0} files" -f $cnt))) {
            $files | Remove-Item -Force -ErrorAction SilentlyContinue
            $tpl = Get-Loc Messages CacheDirCleaned "Cleaned: {0} ({1} files)"
            Write-Log -Message ($tpl -f $d.FullName, $cnt) -Level "INFO" -LogFile $LogFile
            $totalFiles += $cnt
        } else {
            $tpl = Get-Loc Messages CacheDirFoundWhatIf "[WhatIf] Found: {0} ({1} files)"
            Write-Log -Message ($tpl -f $d.FullName, $cnt) -Level "INFO" -LogFile $LogFile
        }

        $totalDirs++
    }

    $tpl = Get-Loc Messages CacheCleanupCompleted "Cache cleanup completed: {0} directories, {1} files"
    Write-Log -Message ($tpl -f $totalDirs, $totalFiles) -Level "SUCCESS" -LogFile $LogFile
}

# -------------------------
# Diagnostic mode
# -------------------------
function Show-Diagnostics {
    Load-1CSettings
    $all = Get-1CRagentServicesFromRegistry
    $sel = Select-1CServicesForMaintenance -AllServices $all

    Write-Host "=== DIAGNOSTICS ==="
    Write-Host ("Language: {0}" -f $Script:LanguageEffective)
    Write-Host ("Discovered ragent.exe services: {0}" -f $all.Count)

    foreach ($s in $all) {
        Write-Host ("- {0} | Role={1} | -d={2}" -f $s.ServiceName, $s.Role, $s.SrvInfoPath)
    }

    Write-Host ""
    Write-Host ("Selected Agent:  {0}" -f (if ($sel.Agent) { $sel.Agent.ServiceName } else { "<none>" }))
    Write-Host ("Selected Server: {0}" -f (if ($sel.Server) { $sel.Server.ServiceName } else { "<none>" }))

    $eff = if ($SrvInfoPath) { $SrvInfoPath } elseif ($sel.Agent -and $sel.Agent.SrvInfoPath) { $sel.Agent.SrvInfoPath } else { $Script:Config.paths.defaultSrvInfo }
    Write-Host ("Effective SrvInfoPath: {0}" -f $eff)
}

# -------------------------
# Main
# -------------------------
function Main {
    Test-Admin
    Load-1CSettings

    if ($Diagnostic) {
        Show-Diagnostics
        return
    }

    $log = Initialize-Logging

    $tpl = Get-Loc Messages ScriptStarted "Cache cleanup started (version {0})."
    $ver = if ($Script:Config.version) { $Script:Config.version } else { "3.1.4" }
    Write-Log -Message ($tpl -f $ver) -Level "INFO" -LogFile $log

    if (-not (Test-Safety -Force:$Force -LogFile $log)) {
        return
    }

    $all = Get-1CRagentServicesFromRegistry
    $sel = Select-1CServicesForMaintenance -AllServices $all

    if (-not $sel.Agent -and -not $sel.Server) {
        $tpl = Get-Loc Messages AgentNotFoundInRegistry "1C ragent services not found in registry. Nothing to do."
        Write-Log -Message $tpl -Level "WARNING" -LogFile $log
        return
    }

    # Determine srvinfo path:
    # - explicit param overrides
    # - then Agent's -d (best)
    # - then Server's -d
    # - then settings default
    $effectiveSrvInfo = $null
    if ($SrvInfoPath) {
        $effectiveSrvInfo = $SrvInfoPath
    } elseif ($sel.Agent -and $sel.Agent.SrvInfoPath) {
        $effectiveSrvInfo = $sel.Agent.SrvInfoPath
    } elseif ($sel.Server -and $sel.Server.SrvInfoPath) {
        $effectiveSrvInfo = $sel.Server.SrvInfoPath
    } elseif ($Script:Config.paths.defaultSrvInfo) {
        $effectiveSrvInfo = $Script:Config.paths.defaultSrvInfo
    }

    if ([string]::IsNullOrWhiteSpace($effectiveSrvInfo)) {
        $tpl = Get-Loc Messages SrvInfoNotDetermined "SrvInfoPath could not be determined from registry. Specify -SrvInfoPath."
        Write-Log -Message $tpl -Level "ERROR" -LogFile $log
        return
    }

    $timeout = if ($PSBoundParameters.ContainsKey("ServiceStopTimeout")) {
        $ServiceStopTimeout
    } elseif ($Script:Config.defaults.serviceStopTimeout) {
        [int]$Script:Config.defaults.serviceStopTimeout
    } else {
        120
    }

    if (-not $NoServiceRestart) {
        $tpl = Get-Loc Messages ServicesStopping "Stopping 1C services..."
        Write-Log -Message $tpl -Level "INFO" -LogFile $log

        # Stop order: Server first, then Agent (your requirement)
        Stop-ServiceSafe -SvcObj $sel.Server -Timeout $timeout -LogFile $log
        Stop-ServiceSafe -SvcObj $sel.Agent  -Timeout $timeout -LogFile $log
    } else {
        Write-Log -Message "Service stop/start is skipped (NoServiceRestart)." -Level "WARNING" -LogFile $log
    }

    Clear-1CCache -Path $effectiveSrvInfo -LogFile $log

    if (-not $NoServiceRestart) {
        $tpl = Get-Loc Messages ServicesStarting "Starting 1C services..."
        Write-Log -Message $tpl -Level "INFO" -LogFile $log

        # Start order: Agent first, then Server
        Start-ServiceSafe -SvcObj $sel.Agent  -LogFile $log
        Start-ServiceSafe -SvcObj $sel.Server -LogFile $log
    }

    $tpl = Get-Loc Messages Completion "Cache cleanup completed successfully."
    Write-Log -Message $tpl -Level "SUCCESS" -LogFile $log

    if ($WhatIfPreference) {
        $tpl = Get-Loc Messages DryRunNotice1 "This was a dry run (WhatIf mode)."
        Write-Log -Message $tpl -Level "INFO" -LogFile $log
    }

    $tpl = Get-Loc Messages LogFilePath "Log file: {0}"
    Write-Log -Message ($tpl -f $log) -Level "INFO" -LogFile $log
}

try {
    Main
} catch {
    $tpl = Get-Loc Messages HintDiagnosticWhatIf "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run."
    Write-Host ("ERROR: {0}" -f $_.Exception.Message)
    Write-Host $tpl
    exit 1
}
