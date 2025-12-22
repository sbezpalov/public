<#
.SYNOPSIS
    1C server cache cleanup (registry-driven) with optional temp cleanup for service accounts.

.DESCRIPTION
    Version 3.1.7
    - Registry is the single source of truth for installed 1C server services (ragent.exe).
    - Stop Server + Agent -> clean srvinfo cache -> (optional) clean service account temp -> start Agent + Server.
    - Native PowerShell -WhatIf / -Confirm via ShouldProcess.
    - Robust localization formatting (no runtime string format errors).
    - ASCII-only script body (UTF only in localization files).
	- Author @sbezpalov ( https://github.com/sbezpalov/public/blob/main/1c/1CClearCache/ )

.NOTES
    Run in a maintenance window. Requires Administrator privileges.
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

    if ([string]::IsNullOrWhiteSpace($Template)) { return "" }
    if (-not $Args -or $Args.Count -eq 0) { return $Template }

    try {
        return $Template -f $Args
    } catch {
        for ($i = $Args.Count - 1; $i -ge 0; $i--) {
            try { return $Template -f $Args[0..$i] } catch { continue }
        }
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
        try {
            $Script:Config = (Get-Content $cfgPath -Raw -Encoding UTF8) | ConvertFrom-Json
        } catch {
            throw ("Failed to read settings.json: {0}" -f $_.Exception.Message)
        }
    } else {
        $Script:Config = [PSCustomObject]@{
            version  = "3.1.7"
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
            tempCleanup = [PSCustomObject]@{
                enabled = $true
                olderThanDays = 7
                includeSystemProfiles = $false
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

    if ($Script:LanguageEffective -notin @("en-US","ru-RU")) {
        $Script:LanguageEffective = "en-US"
    }

    $Script:Localization = Get-1CLocalization -Language $Script:LanguageEffective
}

# =========================
# Logging
# =========================
function Initialize-Logging {
    $dir = $null
    if ($Script:Config -and $Script:Config.paths -and $Script:Config.paths.logDirectory) {
        $dir = [string]$Script:Config.paths.logDirectory
    }
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

# =========================
# Admin check
# =========================
function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $tpl = Get-Loc Messages AdminRequired "Script must be run as Administrator."
        throw $tpl
    }
}

# =========================
# Registry discovery (single source of truth)
# =========================
function Parse-RagentArgs {
    param([string]$ImagePath)

    $h = @{}
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $h }

    $s = [string]$ImagePath

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

            $role = "Agent"
            if ($args.ContainsKey("server") -and -not $args.ContainsKey("agent")) {
                $role = "Server"
            } elseif ($args.ContainsKey("agent") -and -not $args.ContainsKey("server")) {
                $role = "Agent"
            } elseif ($args.ContainsKey("agent") -and $args.ContainsKey("server")) {
                $role = "Agent"
            }

            $srvInfo = $null
            if ($args.ContainsKey("d")) { $srvInfo = [string]$args["d"] }

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

    $agent = $AllServices | Where-Object { $_.Role -eq "Agent" }  | Select-Object -First 1
    $server = $AllServices | Where-Object { $_.Role -eq "Server" } | Select-Object -First 1

    return [PSCustomObject]@{
        Agent  = $agent
        Server = $server
    }
}

# =========================
# Safety checks
# =========================
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

# =========================
# Service account & profile resolution (for temp cleanup)
# =========================
function Get-ServiceStartAccount {
    param([string]$ServiceName)

    try {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
        return [string]$svc.StartName
    } catch {
        return $null
    }
}

function Resolve-AccountSid {
    param([string]$AccountName)

    try {
        $nt = New-Object System.Security.Principal.NTAccount($AccountName)
        $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    } catch {
        return $null
    }
}

function Try-GetProfilePathFromSid {
    param([string]$Sid)

    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    try {
        $p = Get-ItemProperty -Path $key -ErrorAction Stop
        $path = [string]$p.ProfileImagePath
        if ($path -and (Test-Path $path)) { return $path }
    } catch {}
    return $null
}

function Get-ProfilePathForServiceAccount {
    param([string]$StartName)

    if ([string]::IsNullOrWhiteSpace($StartName)) { return $null }

    switch -Regex ($StartName) {
        '^(?i)LocalSystem$' { return "C:\Windows\System32\config\systemprofile" }
        '^(?i)NT AUTHORITY\\LocalService$' { return "C:\Windows\ServiceProfiles\LocalService" }
        '^(?i)NT AUTHORITY\\NetworkService$' { return "C:\Windows\ServiceProfiles\NetworkService" }
    }

    $sid = Resolve-AccountSid -AccountName $StartName
    if (-not $sid) { return $null }

    $path = Try-GetProfilePathFromSid -Sid $sid
    if ($path) { return $path }

    try {
        $up = Get-CimInstance Win32_UserProfile -Filter ("SID='{0}'" -f $sid) -ErrorAction SilentlyContinue
        if ($up -and $up.LocalPath -and (Test-Path $up.LocalPath)) { return [string]$up.LocalPath }
    } catch {}

    return $null
}

function Is-SystemServiceAccount {
    param([string]$StartName)

    if ([string]::IsNullOrWhiteSpace($StartName)) { return $false }

    switch -Regex ($StartName) {
        '^(?i)LocalSystem$' { return $true }
        '^(?i)NT AUTHORITY\\LocalService$' { return $true }
        '^(?i)NT AUTHORITY\\NetworkService$' { return $true }
        default { return $false }
    }
}

function Clear-ServiceAccountTemp {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$StartName,
        [string]$ProfilePath,
        [int]$OlderThanDays = 7,
        [switch]$IncludeSystemProfiles,
        [string]$LogFile
    )

    if ([string]::IsNullOrWhiteSpace($StartName)) { return }
    if ([string]::IsNullOrWhiteSpace($ProfilePath)) { return }

    if ((Is-SystemServiceAccount -StartName $StartName) -and -not $IncludeSystemProfiles) {
        Write-Log -Message ("Temp cleanup skipped for system service account: {0}" -f $StartName) -Level "WARNING" -LogFile $LogFile
        return
    }

    $tempPath = Join-Path $ProfilePath "AppData\Local\Temp"
    if (-not (Test-Path $tempPath)) {
        Write-Log -Message ("Temp path not found: {0}" -f $tempPath) -Level "WARNING" -LogFile $LogFile
        return
    }

    $cutoff = (Get-Date).AddDays(-[int]$OlderThanDays)
    $items = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue
    if (-not $items) {
        Write-Log -Message ("Temp cleanup: nothing found in {0}" -f $tempPath) -Level "INFO" -LogFile $LogFile
        return
    }

    $candidates = $items | Where-Object { $_.LastWriteTime -lt $cutoff }
    $count = ($candidates | Measure-Object).Count
    if ($count -le 0) {
        Write-Log -Message ("Temp cleanup: nothing to delete in {0}" -f $tempPath) -Level "INFO" -LogFile $LogFile
        return
    }

    if ($PSCmdlet.ShouldProcess($tempPath, ("Remove temp items older than {0} days ({1} items) for {2}" -f $OlderThanDays, $count, $StartName))) {
        foreach ($it in $candidates) {
            try {
                Remove-Item -LiteralPath $it.FullName -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Log -Message ("Temp cleanup failed for {0}: {1}" -f $it.FullName, $_.Exception.Message) -Level "WARNING" -LogFile $LogFile
            }
        }
        Write-Log -Message ("Temp cleanup completed: {0} items removed from {1} (account: {2})" -f $count, $tempPath, $StartName) -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message ("[WhatIf] Would remove {0} items from {1} (account: {2})" -f $count, $tempPath, $StartName) -Level "INFO" -LogFile $LogFile
    }
}

# =========================
# Service control (by ServiceName)
# =========================
function Stop-1CServiceSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object]$SvcObj,
        [int]$Timeout,
        [string]$LogFile
    )

    if (-not $SvcObj) { return }

    $name = [string]$SvcObj.ServiceName
    $caption = if ([string]::IsNullOrWhiteSpace($SvcObj.DisplayName)) { $name } else { [string]$SvcObj.DisplayName }

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        $tpl = Get-Loc Messages ServiceNotFound "Service not found: {0}"
        Write-Log -Message (Format-Loc $tpl @($caption)) -Level "WARNING" -LogFile $LogFile
        return
    }

    if ($svc.Status -eq "Stopped") {
        $tpl = Get-Loc Messages ServiceAlreadyStopped "Service already stopped: {0}"
        Write-Log -Message (Format-Loc $tpl @($caption)) -Level "INFO" -LogFile $LogFile
        return
    }

    if ($PSCmdlet.ShouldProcess($caption, "Stop service")) {
        try {
            $tpl = Get-Loc Messages ServiceStopping "Stopping service: {0}"
            Write-Log -Message (Format-Loc $tpl @($caption)) -Level "INFO" -LogFile $LogFile

            Stop-Service -Name $name -Force -ErrorAction Stop
            $svc.WaitForStatus("Stopped", (New-TimeSpan -Seconds $Timeout))

            $tpl = Get-Loc Messages ServiceStopped "Service stopped: {0}"
            Write-Log -Message (Format-Loc $tpl @($caption)) -Level "SUCCESS" -LogFile $LogFile
        } catch {
            $tpl = Get-Loc Messages ServiceStopFailed "Failed to stop service {0}: {1}"
            Write-Log -Message (Format-Loc $tpl @($caption, $_.Exception.Message)) -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

function Start-1CServiceSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object]$SvcObj,
        [string]$LogFile
    )

    if (-not $SvcObj) { return }

    $name = [string]$SvcObj.ServiceName
    $caption = if ([string]::IsNullOrWhiteSpace($SvcObj.DisplayName)) { $name } else { [string]$SvcObj.DisplayName }

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        $tpl = Get-Loc Messages ServiceNotFound "Service not found: {0}"
        Write-Log -Message (Format-Loc $tpl @($caption)) -Level "WARNING" -LogFile $LogFile
        return
    }

    if ($svc.Status -eq "Running") {
        return
    }

    if ($PSCmdlet.ShouldProcess($caption, "Start service")) {
        try {
            $tpl = Get-Loc Messages ServiceStarting "Starting service: {0}"
            Write-Log -Message (Format-Loc $tpl @($caption)) -Level "INFO" -LogFile $LogFile

            Start-Service -Name $name -ErrorAction Stop

            $tpl = Get-Loc Messages ServiceStarted "Service started: {0}"
            Write-Log -Message (Format-Loc $tpl @($caption)) -Level "SUCCESS" -LogFile $LogFile
        } catch {
            $tpl = Get-Loc Messages ServiceStartFailed "Failed to start service {0}: {1}"
            Write-Log -Message (Format-Loc $tpl @($caption, $_.Exception.Message)) -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

# =========================
# Cache cleanup (srvinfo)
# =========================
function Clear-1CServerCacheDirs {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$SrvInfo,
        [string]$LogFile
    )

    $tpl = Get-Loc Messages CleanupStarting "Starting cache cleanup: {0}"
    Write-Log -Message (Format-Loc $tpl @($SrvInfo)) -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $SrvInfo)) {
        $tpl = Get-Loc Messages PathNotFound "Path not found: {0}"
        $msg = Format-Loc $tpl @($SrvInfo)
        Write-Log -Message $msg -Level "ERROR" -LogFile $LogFile
        throw $msg
    }

    $dirs = Get-ChildItem -Path $SrvInfo -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    if (-not $dirs) {
        $tpl = Get-Loc Messages CacheDirsNotFound "No cache directories found under {0}"
        Write-Log -Message (Format-Loc $tpl @($SrvInfo)) -Level "WARNING" -LogFile $LogFile
        return
    }

    $totalDirs = 0
    $totalFiles = 0

    foreach ($d in $dirs) {
        try {
            $files = Get-ChildItem -Path $d.FullName -File -Recurse -ErrorAction SilentlyContinue
            $cnt = $files.Count
            if ($cnt -le 0) { continue }

            if ($PSCmdlet.ShouldProcess($d.FullName, ("Remove {0} cache files" -f $cnt))) {
                $files | Remove-Item -Force -ErrorAction SilentlyContinue

                $tpl = Get-Loc Messages CacheDirCleaned "Cleaned: {0} ({1} files)"
                Write-Log -Message (Format-Loc $tpl @($d.FullName, $cnt)) -Level "INFO" -LogFile $LogFile

                $totalDirs++
                $totalFiles += $cnt
            } else {
                $tpl = Get-Loc Messages CacheDirFoundWhatIf "[WhatIf] Found cache directory: {0} ({1} files)"
                Write-Log -Message (Format-Loc $tpl @($d.FullName, $cnt)) -Level "INFO" -LogFile $LogFile
            }
        } catch {
            $tpl = Get-Loc Messages CacheDirCleanError "Error cleaning {0}: {1}"
            Write-Log -Message (Format-Loc $tpl @($d.FullName, $_.Exception.Message)) -Level "WARNING" -LogFile $LogFile
        }
    }

    $tpl = Get-Loc Messages CacheCleanupCompleted "Cache cleanup completed: {0} directories, {1} files"
    Write-Log -Message (Format-Loc $tpl @($totalDirs, $totalFiles)) -Level "SUCCESS" -LogFile $LogFile
}

# =========================
# Diagnostics
# =========================
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

    if ($sel.Agent) {
        $acc = Get-ServiceStartAccount -ServiceName $sel.Agent.ServiceName
        Write-Host ("Agent StartName: {0}" -f $acc)
    }
    if ($sel.Server) {
        $acc = Get-ServiceStartAccount -ServiceName $sel.Server.ServiceName
        Write-Host ("Server StartName: {0}" -f $acc)
    }

    $eff = if ($SrvInfoPath) { $SrvInfoPath } elseif ($sel.Agent -and $sel.Agent.SrvInfoPath) { $sel.Agent.SrvInfoPath } elseif ($Script:Config.paths.defaultSrvInfo) { $Script:Config.paths.defaultSrvInfo } else { "" }
    Write-Host ("Effective SrvInfoPath: {0}" -f $eff)
}

# =========================
# Main
# =========================
function Main {
    Test-Admin
    Load-1CSettings

    if ($Diagnostic) {
        Show-Diagnostics
        return
    }

    $log = Initialize-Logging

    $ver = if ($Script:Config.version) { [string]$Script:Config.version } else { "3.1.7" }
    $tpl = Get-Loc Messages ScriptStarted "Cache cleanup started (version {0})."
    Write-Log -Message (Format-Loc $tpl @($ver)) -Level "INFO" -LogFile $log

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

        Stop-1CServiceSafe -SvcObj $sel.Server -Timeout $timeout -LogFile $log
        Stop-1CServiceSafe -SvcObj $sel.Agent  -Timeout $timeout -LogFile $log
    } else {
        Write-Log -Message "Service stop/start is skipped (NoServiceRestart)." -Level "WARNING" -LogFile $log
    }

    Clear-1CServerCacheDirs -SrvInfo $effectiveSrvInfo -LogFile $log

    # Optional: clean temp for service account(s) only if 1C services run under those accounts.
    $tempEnabled = $false
    $olderThanDays = 7
    $includeSystemProfiles = $false

    if ($Script:Config.tempCleanup) {
        if ($Script:Config.tempCleanup.enabled -ne $null) { $tempEnabled = [bool]$Script:Config.tempCleanup.enabled }
        if ($Script:Config.tempCleanup.olderThanDays) { $olderThanDays = [int]$Script:Config.tempCleanup.olderThanDays }
        if ($Script:Config.tempCleanup.includeSystemProfiles -ne $null) { $includeSystemProfiles = [bool]$Script:Config.tempCleanup.includeSystemProfiles }
    }

    if ($tempEnabled) {
        $accounts = New-Object System.Collections.Generic.HashSet[string]

        foreach ($svcObj in @($sel.Agent, $sel.Server)) {
            if (-not $svcObj) { continue }
            $startName = Get-ServiceStartAccount -ServiceName $svcObj.ServiceName
            if ([string]::IsNullOrWhiteSpace($startName)) { continue }
            [void]$accounts.Add($startName)
        }

        foreach ($acc in $accounts) {
            # User requirement: clean user cache only for the account used to start 1C services.
            # Policy: skip system accounts by default.
            if ((Is-SystemServiceAccount -StartName $acc) -and -not $includeSystemProfiles) {
                Write-Log -Message ("Temp cleanup skipped for system account: {0}" -f $acc) -Level "INFO" -LogFile $log
                continue
            }

            $profile = Get-ProfilePathForServiceAccount -StartName $acc
            if ([string]::IsNullOrWhiteSpace($profile)) {
                Write-Log -Message ("Profile path not found for service account: {0}" -f $acc) -Level "WARNING" -LogFile $log
                continue
            }

            Clear-ServiceAccountTemp -StartName $acc -ProfilePath $profile -OlderThanDays $olderThanDays -IncludeSystemProfiles:($includeSystemProfiles) -LogFile $log
        }
    }

    if (-not $NoServiceRestart) {
        $tpl = Get-Loc Messages ServicesStarting "Starting 1C services..."
        Write-Log -Message $tpl -Level "INFO" -LogFile $log

        Start-1CServiceSafe -SvcObj $sel.Agent  -LogFile $log
        Start-1CServiceSafe -SvcObj $sel.Server -LogFile $log
    }

    $tpl = Get-Loc Messages Completion "Cache cleanup completed successfully."
    Write-Log -Message $tpl -Level "SUCCESS" -LogFile $log

    $tpl = Get-Loc Messages LogFilePath "Log file: {0}"
    Write-Log -Message (Format-Loc $tpl @($log)) -Level "INFO" -LogFile $log

    if ($WhatIfPreference) {
        $tpl = Get-Loc Messages DryRunNotice1 "This was a dry run (WhatIf mode)."
        Write-Log -Message $tpl -Level "INFO" -LogFile $log
    }
}

try {
    Main
} catch {
    $tpl = Get-Loc Messages HintDiagnosticWhatIf "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run."
    Write-Host ("ERROR: {0}" -f $_.Exception.Message)
    Write-Host $tpl
    exit 1
}
