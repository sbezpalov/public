<#
.SYNOPSIS
    Professional 1C server cache cleanup with automatic registry-based configuration detection.

.DESCRIPTION
    Version 3.1.2
    - Uses settings.json for configuration (paths, logging, safety).
    - Uses localization (en-US / ru-RU) from psd1 files.
    - Uses PowerShell native ShouldProcess for -WhatIf / -Confirm (no custom WhatIf parameter).

.VERSION
    3.1.2
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

# Configuration from settings.json
$Script:Config = $null
# Localization data (Messages, Prompts, ServiceNames, Diagnostics)
$Script:Localization = $null
# Effective language
$Script:LanguageEffective = "en-US"

function Get-Loc {
    param(
        [string]$Section,
        [string]$Key,
        [string]$Fallback = ""
    )
    try {
        $obj = $Script:Localization
        if (-not $obj) { return $Fallback }
        $sectionObj = $obj.$Section
        if (-not $sectionObj) { return $Fallback }
        $val = $sectionObj.$Key
        if ([string]::IsNullOrWhiteSpace($val)) { return $Fallback }
        return $val
    } catch {
        return $Fallback
    }
}

# =========================
# LOCALIZATION
# =========================

function Get-1CLocalization {
    param(
        [string]$Language
    )

    $LocalizationPath = Join-Path $PSScriptRoot "Localization"
    $LocalizationFile = Join-Path $LocalizationPath "$Language.psd1"

    if (Test-Path $LocalizationFile) {
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "$Language.psd1"
    }

    return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "en-US.psd1"
}

# =========================
# SETTINGS AND INIT
# =========================

function Load-1CSettings {
    $ConfigPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $ConfigPath) {
        try {
            $json = Get-Content $ConfigPath -Raw -Encoding UTF8
            $Script:Config = $json | ConvertFrom-Json
        } catch {
            throw ("Failed to read settings.json: {0}" -f $_.Exception.Message)
        }
    } else {
        $Script:Config = [PSCustomObject]@{
            version  = "3.1.2"
            author   = "1C Server Automation Community"
            defaults = [PSCustomObject]@{
                serviceStopTimeout = 120
                language           = "auto"
                logRetentionDays   = 30
            }
            paths    = [PSCustomObject]@{
                defaultSrvInfo = "C:\Program Files\1cv8\srvinfo"
                logDirectory   = "C:\Scripts\Logs\1C_Maintenance"
            }
            safety   = [PSCustomObject]@{
                checkActiveSessions = $true
                requireConfirmation = $false
                enableBackup        = $false
            }
            serviceNames = $null
            logging      = [PSCustomObject]@{
                level          = "INFO"
                maxFileSizeMB  = 10
                enableEventLog = $true
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('Language') -and $Language) {
        $Script:LanguageEffective = $Language
    } else {
        $defaultLang = $Script:Config.defaults.language
        if ([string]::IsNullOrWhiteSpace($defaultLang) -or $defaultLang -eq "auto") {
            $Script:LanguageEffective = (Get-Culture).Name
        } else {
            $Script:LanguageEffective = $defaultLang
        }
    }

    if ($Script:LanguageEffective -notin @("en-US", "ru-RU")) {
        $Script:LanguageEffective = "en-US"
    }

    $Script:Localization = Get-1CLocalization -Language $Script:LanguageEffective
}

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $msg = Get-Loc -Section "Messages" -Key "AdminRequired" -Fallback "Script must be run as Administrator."
        throw $msg
    }
}

# =========================
# REGISTRY / 1C DISCOVERY
# =========================

function Get-1CAgentServiceInfo {
    $AgentPatterns = @(
        "1C:Enterprise 8.3 Server Agent*",
        "1C:Enterprise 8.3 Server Agent (x86-64)*",
        "1C:Enterprise 8.2 Server Agent*"
    )

    foreach ($Pattern in $AgentPatterns) {
        $Services = Get-Service -DisplayName $Pattern -ErrorAction SilentlyContinue
        if (-not $Services) { continue }

        $Service = $Services[0]
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)"
        if (-not (Test-Path $RegPath)) { continue }

        $RegProperties = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
        if (-not ($RegProperties -and $RegProperties.ImagePath)) { continue }

        $Parameters = @{}
        if ($RegProperties.ImagePath -match 'ragent\.exe\s+(.*)$') {
            $ArgsString = $Matches[1]
            $Tokens = $ArgsString -split '\s+' | Where-Object { $_ }

            for ($i = 0; $i -lt $Tokens.Count; $i++) {
                if ($Tokens[$i] -match '^-(\w+)$') {
                    $ParamName = $Matches[1]
                    if ($i + 1 -lt $Tokens.Count -and $Tokens[$i + 1] -notmatch '^-') {
                        $Parameters[$ParamName] = $Tokens[$i + 1].Trim('"')
                        $i++
                    } else {
                        $Parameters[$ParamName] = $true
                    }
                }
            }
        }

        $DetectedSrvInfo = $null
        if ($Parameters.ContainsKey('d')) {
            $DetectedSrvInfo = $Parameters['d']
        }

        $Version = $null
        if ($RegProperties.ImagePath -match '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') {
            $Version = $Matches[1]
        }

        return [PSCustomObject]@{
            ServiceName = $Service.Name
            DisplayName = $Service.DisplayName
            ImagePath   = $RegProperties.ImagePath
            Parameters  = $Parameters
            SrvInfoPath = $DetectedSrvInfo
            Version     = $Version
        }
    }

    return $null
}

function Get-1CClusterNodes {
    param(
        [string]$SrvInfoPath
    )

    $Nodes = @()
    $ClusterRegPath = Join-Path $SrvInfoPath "reg_1cv8"

    if (-not (Test-Path $ClusterRegPath)) { return $Nodes }

    $RegFiles = Get-ChildItem -Path $ClusterRegPath -Filter "*.reg" -ErrorAction SilentlyContinue
    foreach ($RegFile in $RegFiles) {
        $Content = Get-Content $RegFile.FullName -Raw -ErrorAction SilentlyContinue
        if ($Content -match '"AgentHost"="([^"]+)"') {
            $NodeInfo = @{
                NodeName = $Matches[1]
                RegFile  = $RegFile.FullName
            }
            if ($Content -match '"AgentPort"="(\d+)"') {
                $NodeInfo.AgentPort = [int]$Matches[1]
            }
            $Nodes += [PSCustomObject]$NodeInfo
        }
    }

    return $Nodes
}

function Get-1CFullConfiguration {
    $AgentService = Get-1CAgentServiceInfo

    $SrvInfo = if ($AgentService -and $AgentService.SrvInfoPath) {
        $AgentService.SrvInfoPath
    } elseif ($Script:Config -and $Script:Config.paths.defaultSrvInfo) {
        $Script:Config.paths.defaultSrvInfo
    } else {
        $null
    }

    $ClusterNodes = @()
    if ($SrvInfo) {
        $ClusterNodes = Get-1CClusterNodes -SrvInfoPath $SrvInfo
    }

    return [PSCustomObject]@{
        AgentService = $AgentService
        SrvInfoPath  = $SrvInfo
        ClusterNodes = $ClusterNodes
    }
}

# =========================
# LOGGING
# =========================

function Initialize-Logging {
    param(
        [object]$Config
    )

    $LogDir = if ($Config -and $Config.paths -and $Config.paths.logDirectory) {
        $Config.paths.logDirectory
    } else {
        "C:\Scripts\Logs\1C_Maintenance"
    }

    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    $RetentionDays = 0
    if ($Config -and $Config.defaults -and $Config.defaults.logRetentionDays) {
        $RetentionDays = [int]$Config.defaults.logRetentionDays
    }

    if ($RetentionDays -gt 0) {
        $Threshold = (Get-Date).AddDays(-$RetentionDays)
        Get-ChildItem -Path $LogDir -Filter "1CCacheCleaner_*.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Threshold } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    return (Join-Path $LogDir ("1CCacheCleaner_{0}.log" -f $Timestamp))
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [string]$LogFile
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Formatted = "[{0}] [{1}] {2}" -f $Timestamp, $Level, $Message

    $minLevel = "INFO"
    if ($Script:Config -and $Script:Config.logging -and $Script:Config.logging.level) {
        $minLevel = $Script:Config.logging.level.ToUpper()
    }

    $Order = @{
        "DEBUG"   = 0
        "INFO"    = 1
        "SUCCESS" = 1
        "WARNING" = 2
        "ERROR"   = 3
    }

    $levelKey = $Level.ToUpper()
    if (-not $Order.ContainsKey($levelKey)) { $levelKey = "INFO" }
    $minKey = if ($Order.ContainsKey($minLevel)) { $minLevel } else { "INFO" }
    if ($Order[$levelKey] -lt $Order[$minKey]) { return }

    $Colors = @{
        DEBUG   = "DarkGray"
        INFO    = "White"
        WARNING = "Yellow"
        ERROR   = "Red"
        SUCCESS = "Green"
    }
    $color = if ($Colors.ContainsKey($levelKey)) { $Colors[$levelKey] } else { "White" }
    Write-Host $Formatted -ForegroundColor $color

    if ($LogFile) {
        $Formatted | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    if ($Script:Config -and $Script:Config.logging.enableEventLog -and $levelKey -in @("ERROR", "WARNING")) {
        try {
            $sourceName = "1C Cache Cleaner"
            if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($sourceName, "Application")
            }
            $EventId = switch ($levelKey) {
                "ERROR"   { 1001 }
                "WARNING" { 1002 }
                default   { 1000 }
            }
            Write-EventLog -LogName "Application" -Source $sourceName -EventId $EventId -EntryType $levelKey -Message $Message
        } catch {
            # Do not break main flow on EventLog failures
        }
    }
}

# =========================
# SAFETY
# =========================

function Test-Safety {
    param(
        [switch]$Force,
        [string]$LogFile
    )

    if ($Force) {
        Write-Log -Message (Get-Loc -Section "Messages" -Key "ForceSkipsSafety" -Fallback "Force is set: safety checks are skipped.") -Level "WARNING" -LogFile $LogFile
        return $true
    }

    if ($Script:Config -and $Script:Config.safety -and -not $Script:Config.safety.checkActiveSessions) {
        Write-Log -Message (Get-Loc -Section "Messages" -Key "ActiveSessionCheckDisabled" -Fallback "Active session check is disabled in settings.json.") -Level "WARNING" -LogFile $LogFile
        return $true
    }

    $Processes1C = Get-Process -Name "1cv8", "1cv8c", "1cv8s" -ErrorAction SilentlyContinue
    if ($Processes1C) {
        $warningText = Get-Loc -Section "Prompts" -Key "WarningActiveSessions" -Fallback "WARNING: Active 1C processes found."
        Write-Host $warningText -ForegroundColor Red -BackgroundColor Black

        foreach ($p in $Processes1C) {
            Write-Host ("  - {0} (PID: {1})" -f $p.ProcessName, $p.Id) -ForegroundColor Red
        }

        Write-Log -Message (Get-Loc -Section "Messages" -Key "SafetyCheckFailed" -Fallback "Safety check failed: active 1C processes detected.") -Level "ERROR" -LogFile $LogFile

        if ($Script:Config.safety.requireConfirmation) {
            $prompt = Get-Loc -Section "Prompts" -Key "ConfirmCleanup" -Fallback "Proceed with cache cleanup? [Y/N]: "
            $answer = Read-Host $prompt
            if ($answer -notin @("Y", "y", "Yes", "YES")) {
                return $false
            }
            return $true
        }

        return $false
    }

    Write-Log -Message (Get-Loc -Section "Messages" -Key "SafetyCheckPassed" -Fallback "Safety check passed.") -Level "INFO" -LogFile $LogFile
    return $true
}

# =========================
# SERVICE CONTROL
# =========================

function Resolve-1CServiceByDisplayName {
    param(
        [string]$DisplayName
    )
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $null }
    return Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Stop-1CServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ServiceDisplayNames,
        [int]$Timeout,
        [string]$LogFile
    )

    $Stopped = @()

    foreach ($DisplayName in $ServiceDisplayNames) {
        $svc = Resolve-1CServiceByDisplayName -DisplayName $DisplayName
        if (-not $svc) {
            Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceNotFound" -Fallback ("Service not found: {0}" -f $DisplayName)) -Level "WARNING" -LogFile $LogFile
            continue
        }

        if ($svc.Status -eq 'Stopped') {
            Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceAlreadyStopped" -Fallback ("Service already stopped: {0}" -f $DisplayName)) -Level "INFO" -LogFile $LogFile
            $Stopped += $DisplayName
            continue
        }

        if ($PSCmdlet.ShouldProcess($DisplayName, "Stop service")) {
            try {
                Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceStopping" -Fallback ("Stopping service: {0}" -f $DisplayName)) -Level "INFO" -LogFile $LogFile
                Stop-Service -Name $svc.Name -Force
                $svc.WaitForStatus('Stopped', (New-TimeSpan -Seconds $Timeout))
                Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceStopped" -Fallback ("Service stopped: {0}" -f $DisplayName)) -Level "SUCCESS" -LogFile $LogFile
                $Stopped += $DisplayName
            } catch {
                $err = ("Failed to stop service {0}: {1}" -f $DisplayName, $_.Exception.Message)
                Write-Log -Message $err -Level "ERROR" -LogFile $LogFile
                throw
            }
        } else {
            # -WhatIf path
            Write-Log -Message ("[WhatIf] Would stop service: {0}" -f $DisplayName) -Level "INFO" -LogFile $LogFile
            $Stopped += $DisplayName
        }
    }

    Start-Sleep -Seconds 3
    return $Stopped
}

function Start-1CServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ServiceDisplayNames,
        [string]$LogFile
    )

    foreach ($DisplayName in $ServiceDisplayNames) {
        $svc = Resolve-1CServiceByDisplayName -DisplayName $DisplayName
        if (-not $svc) {
            Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceNotFound" -Fallback ("Service not found: {0}" -f $DisplayName)) -Level "WARNING" -LogFile $LogFile
            continue
        }

        if ($PSCmdlet.ShouldProcess($DisplayName, "Start service")) {
            try {
                Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceStarting" -Fallback ("Starting service: {0}" -f $DisplayName)) -Level "INFO" -LogFile $LogFile
                Start-Service -Name $svc.Name
                Start-Sleep -Seconds 5
                $Status = (Get-Service -Name $svc.Name).Status
                Write-Log -Message (Get-Loc -Section "Messages" -Key "ServiceStarted" -Fallback ("Service started: {0} (Status: {1})" -f $DisplayName, $Status)) -Level "SUCCESS" -LogFile $LogFile
            } catch {
                $err = ("Failed to start service {0}: {1}" -f $DisplayName, $_.Exception.Message)
                Write-Log -Message $err -Level "ERROR" -LogFile $LogFile
                throw
            }
        } else {
            Write-Log -Message ("[WhatIf] Would start service: {0}" -f $DisplayName) -Level "INFO" -LogFile $LogFile
        }
    }
}

# =========================
# CACHE CLEANUP
# =========================

function Clear-1CCache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$SrvInfoPath,
        [string]$LogFile
    )

    Write-Log -Message (Get-Loc -Section "Messages" -Key "CleanupStarting" -Fallback ("Starting cache cleanup: {0}" -f $SrvInfoPath)) -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $SrvInfoPath)) {
        $m = Get-Loc -Section "Messages" -Key "PathNotFound" -Fallback ("Path not found: {0}" -f $SrvInfoPath)
        Write-Log -Message $m -Level "ERROR" -LogFile $LogFile
        throw $m
    }

    $CacheDirs = Get-ChildItem -Path $SrvInfoPath -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    if (-not $CacheDirs) {
        Write-Log -Message (Get-Loc -Section "Messages" -Key "CacheDirsNotFound" -Fallback ("No cache directories found under {0}" -f $SrvInfoPath)) -Level "WARNING" -LogFile $LogFile
        return
    }

    $TotalDirs = 0
    $TotalFiles = 0

    foreach ($Dir in $CacheDirs) {
        try {
            $Files = Get-ChildItem -Path $Dir.FullName -File -Recurse -ErrorAction SilentlyContinue
            $FileCount = $Files.Count

            if ($FileCount -le 0) {
                $TotalDirs++
                continue
            }

            if ($PSCmdlet.ShouldProcess($Dir.FullName, ("Remove {0} files" -f $FileCount))) {
                $Files | Remove-Item -Force -ErrorAction SilentlyContinue
                $msg = Get-Loc -Section "Messages" -Key "CacheDirCleaned" -Fallback ("Cleaned: {0} ({1} files)" -f $Dir.FullName, $FileCount)
                Write-Log -Message $msg -Level "INFO" -LogFile $LogFile
                $TotalFiles += $FileCount
            } else {
                $msg = Get-Loc -Section "Messages" -Key "CacheDirFoundWhatIf" -Fallback ("[WhatIf] Found cache directory: {0} ({1} files)" -f $Dir.FullName, $FileCount)
                Write-Log -Message $msg -Level "INFO" -LogFile $LogFile
            }

            $TotalDirs++
        } catch {
            $msg = Get-Loc -Section "Messages" -Key "CacheDirCleanError" -Fallback ("Error cleaning {0}: {1}" -f $Dir.FullName, $_.Exception.Message)
            Write-Log -Message $msg -Level "ERROR" -LogFile $LogFile
        }
    }

    $final = Get-Loc -Section "Messages" -Key "CacheCleanupCompleted" -Fallback ("Cache cleanup completed: {0} directories, {1} files" -f $TotalDirs, $TotalFiles)
    Write-Log -Message $final -Level "SUCCESS" -LogFile $LogFile
}

# =========================
# DIAGNOSTICS
# =========================

function Show-Diagnostics {
    $Config = Get-1CFullConfiguration

    Write-Host (Get-Loc -Section "Diagnostics" -Key "Header" -Fallback "=== 1C SERVER DIAGNOSTICS ===") -ForegroundColor Cyan
    Write-Host ""

    if ($Config.AgentService) {
        Write-Host (Get-Loc -Section "Diagnostics" -Key "AgentServiceHeader" -Fallback "AGENT SERVICE:") -ForegroundColor Green
        Write-Host ("  Display name: {0}" -f $Config.AgentService.DisplayName) -ForegroundColor Yellow
        Write-Host ("  Version:      {0}" -f $Config.AgentService.Version) -ForegroundColor Gray

        $notDetected = Get-Loc -Section "Diagnostics" -Key "NotDetected" -Fallback "<not detected>"
        $srvInfo = if ($Config.AgentService.SrvInfoPath) { $Config.AgentService.SrvInfoPath } else { $notDetected }
        Write-Host ("  SrvInfo path: {0}" -f $srvInfo) -ForegroundColor (if ($Config.AgentService.SrvInfoPath) { "Green" } else { "Red" })

        if ($Config.AgentService.Parameters.Count -gt 0) {
            Write-Host (Get-Loc -Section "Diagnostics" -Key "ParametersHeader" -Fallback "  Parameters:") -ForegroundColor Gray
            foreach ($key in $Config.AgentService.Parameters.Keys) {
                Write-Host ("    -{0} : {1}" -f $key, $Config.AgentService.Parameters[$key]) -ForegroundColor Gray
            }
        }
    } else {
        Write-Host (Get-Loc -Section "Diagnostics" -Key "AgentNotFound" -Fallback "Agent service not found.") -ForegroundColor Red
    }

    Write-Host ""
    Write-Host (Get-Loc -Section "Diagnostics" -Key "ClustersHeader" -Fallback "CLUSTERS:") -ForegroundColor Green
    if ($Config.ClusterNodes.Count -gt 0) {
        foreach ($node in $Config.ClusterNodes) {
            Write-Host ("  Node: {0} (port: {1})" -f $node.NodeName, $node.AgentPort) -ForegroundColor Gray
            Write-Host ("    Reg file: {0}" -f $node.RegFile) -ForegroundColor DarkGray
        }
    } else {
        Write-Host (Get-Loc -Section "Diagnostics" -Key "ClusterNotFound" -Fallback "  Cluster information not found.") -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host (Get-Loc -Section "Diagnostics" -Key "SafetyHeader" -Fallback "SAFETY:") -ForegroundColor Green
    $Safe = Test-Safety
    $ActiveNone = Get-Loc -Section "Diagnostics" -Key "ActiveNone" -Fallback "NO active 1C processes"
    $ActiveDetected = Get-Loc -Section "Diagnostics" -Key "ActiveDetected" -Fallback "ACTIVE 1C processes detected"
    $statusText = if ($Safe) { $ActiveNone } else { $ActiveDetected }
    Write-Host ("  Active sessions: {0}" -f $statusText) -ForegroundColor (if ($Safe) { "Green" } else { "Red" })

    Write-Host ""
    Write-Host (Get-Loc -Section "Diagnostics" -Key "RecommendedCmdHeader" -Fallback "RECOMMENDED COMMAND:") -ForegroundColor Cyan
    $Cmd = ".\Clear-1CServerCache.ps1"
    if ($Config.SrvInfoPath) { $Cmd += " -SrvInfoPath `"$($Config.SrvInfoPath)`"" }
    if ($Script:LanguageEffective -eq "ru-RU") { $Cmd += " -Language ru-RU" }
    Write-Host ("  {0}" -f $Cmd) -ForegroundColor Yellow
}

# =========================
# MAIN
# =========================

function Main {
    Test-Admin
    Load-1CSettings

    if ($Diagnostic) {
        Show-Diagnostics
        return
    }

    $LogFile = Initialize-Logging -Config $Script:Config

    $scriptStarted = Get-Loc -Section "Messages" -Key "ScriptStarted" -Fallback "1C Server Cache Cleaner started (version {0})."
    Write-Log -Message ($scriptStarted -f $Script:Config.version) -Level "INFO" -LogFile $LogFile

    $Config = Get-1CFullConfiguration

    $TargetPath = if ($SrvInfoPath) {
        $SrvInfoPath
    } elseif ($Config.SrvInfoPath) {
        $Config.SrvInfoPath
    } elseif ($Script:Config.paths.defaultSrvInfo) {
        $Script:Config.paths.defaultSrvInfo
    } else {
        $null
    }

    if (-not $TargetPath) {
        $m = Get-Loc -Section "Messages" -Key "SrvInfoNotDetermined" -Fallback "SrvInfoPath could not be determined. Specify -SrvInfoPath or configure it in settings.json."
        Write-Log -Message $m -Level "ERROR" -LogFile $LogFile
        return
    }

    if ($TargetPath -notmatch '\\srvinfo(\\|$)') {
        $m = Get-Loc -Section "Messages" -Key "SrvInfoPathUnusual" -Fallback ("SrvInfoPath looks unusual: {0}" -f $TargetPath)
        Write-Log -Message $m -Level "WARNING" -LogFile $LogFile

        if (-not $Force) {
            $m2 = Get-Loc -Section "Messages" -Key "SrvInfoPathUnusualNeedForce" -Fallback "Use -Force to work with non-standard SrvInfoPath."
            Write-Log -Message $m2 -Level "ERROR" -LogFile $LogFile
            return
        }
    }

    $EffectiveTimeout = if ($PSBoundParameters.ContainsKey("ServiceStopTimeout")) {
        $ServiceStopTimeout
    } elseif ($Script:Config.defaults.serviceStopTimeout) {
        [int]$Script:Config.defaults.serviceStopTimeout
    } else {
        120
    }

    $ServiceDisplayAgent = $null
    $ServiceDisplayServer = $null

    if ($Script:Config.serviceNames) {
        $ServiceDisplayAgent = $Script:Config.serviceNames.agent[$Script:LanguageEffective]
        $ServiceDisplayServer = $Script:Config.serviceNames.server[$Script:LanguageEffective]
    }

    if (-not $ServiceDisplayAgent) { $ServiceDisplayAgent = Get-Loc -Section "ServiceNames" -Key "Agent" -Fallback $null }
    if (-not $ServiceDisplayServer) { $ServiceDisplayServer = Get-Loc -Section "ServiceNames" -Key "Server" -Fallback $null }

    $ServicesToManage = @()
    if ($ServiceDisplayAgent) { $ServicesToManage += $ServiceDisplayAgent }
    if ($ServiceDisplayServer) { $ServicesToManage += $ServiceDisplayServer }

    if ($Script:Config.safety.requireConfirmation -and -not $Force) {
        $prompt = Get-Loc -Section "Prompts" -Key "ConfirmCleanup" -Fallback "Proceed with cache cleanup? [Y/N]: "
        $answer = Read-Host $prompt
        if ($answer -notin @("Y", "y", "Yes", "YES")) {
            Write-Log -Message "Operation cancelled by user." -Level "WARNING" -LogFile $LogFile
            return
        }
    }

    if (-not (Test-Safety -Force:$Force -LogFile $LogFile)) {
        $m = Get-Loc -Section "Messages" -Key "SafetyCheckFailed" -Fallback "Safety check failed."
        Write-Log -Message $m -Level "ERROR" -LogFile $LogFile
        Write-Host $m -ForegroundColor Red
        return
    }

    $StoppedServices = @()

    if (-not $NoServiceRestart -and $ServicesToManage.Count -gt 0) {
        Write-Log -Message (Get-Loc -Section "Messages" -Key "ServicesStopping" -Fallback "Stopping 1C services...") -Level "INFO" -LogFile $LogFile
        $StoppedServices = Stop-1CServices -ServiceDisplayNames $ServicesToManage -Timeout $EffectiveTimeout -LogFile $LogFile
    } else {
        Write-Log -Message "Service stop is skipped." -Level "INFO" -LogFile $LogFile
    }

    Clear-1CCache -SrvInfoPath $TargetPath -LogFile $LogFile

    if (-not $NoServiceRestart -and $StoppedServices.Count -gt 0) {
        Write-Log -Message (Get-Loc -Section "Messages" -Key "ServicesStarting" -Fallback "Starting 1C services...") -Level "INFO" -LogFile $LogFile
        Start-1CServices -ServiceDisplayNames $StoppedServices -LogFile $LogFile
    }

    $completeMsg = Get-Loc -Section "Messages" -Key "Completion" -Fallback "Cache cleanup completed successfully."
    Write-Log -Message $completeMsg -Level "SUCCESS" -LogFile $LogFile

    Write-Host $completeMsg -ForegroundColor Green
    Write-Host ((Get-Loc -Section "Messages" -Key "LogFilePath" -Fallback "Log file: {0}") -f $LogFile) -ForegroundColor Gray

    if ($WhatIfPreference) {
        Write-Host (Get-Loc -Section "Messages" -Key "DryRunNotice1" -Fallback "This was a dry run (WhatIf mode).") -ForegroundColor Yellow
        Write-Host (Get-Loc -Section "Messages" -Key "DryRunNotice2" -Fallback "Run without -WhatIf to perform actual cleanup.") -ForegroundColor Yellow
    }
}

# =========================
# SCRIPT START
# =========================

try {
    Main
} catch {
    $err = ("ERROR: {0}" -f $_.Exception.Message)
    Write-Host $err -ForegroundColor Red
    Write-Host (Get-Loc -Section "Messages" -Key "HintDiagnosticWhatIf" -Fallback "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run.") -ForegroundColor Yellow
    exit 1
}
