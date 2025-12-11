<#
.SYNOPSIS
    Professional 1C server cache cleanup with automatic registry-based configuration detection.

.DESCRIPTION
    Version 3.1.0
    - Automatically discovers 1C server configuration from Windows registry (SrvInfoPath, version, etc.).
    - Supports clusters (reg_1cv8 analysis).
    - Uses settings.json for configuration (paths, logging, safety).
    - Uses localization (en-US / ru-RU) from psd1 files.

.AUTHOR
    1C Server Automation Community

.VERSION
    3.1.0

.PARAMETER ServiceStopTimeout
    Service stop timeout in seconds (default: settings.json -> defaults.serviceStopTimeout).

.PARAMETER SrvInfoPath
    Explicit srvinfo path (if auto detection is not possible or needs to be overridden).

.PARAMETER Language
    UI language: en-US or ru-RU.
    If not specified, settings.json defaults.language is used:
        - "auto"   -> current system culture
        - "en-US" / "ru-RU" -> explicit language

.PARAMETER WhatIf
    Dry run mode: no real service stop or file deletion.

.PARAMETER Diagnostic
    Diagnostic mode: prints 1C configuration info (no cleanup).

.PARAMETER Force
    Skip safety checks (active sessions and path sanity).
    WARNING: use only if you understand the risks.

.PARAMETER NoServiceRestart
    Do not stop or start 1C services (not recommended for cache cleanup).

.EXAMPLE
    .\Clear-1CServerCache.ps1
    Standard cleanup using settings.json configuration.

.EXAMPLE
    .\Clear-1CServerCache.ps1 -SrvInfoPath "C:\Program Files\1cv8\srvinfo"
    Cleanup using explicitly specified srvinfo path.

.EXAMPLE
    .\Clear-1CServerCache.ps1 -WhatIf
    Dry run without actual cleanup.

.EXAMPLE
    .\Clear-1CServerCache.ps1 -Language ru-RU
    Cleanup with Russian UI.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [int]$ServiceStopTimeout = 120,
    [string]$SrvInfoPath,
    [ValidateSet("en-US", "ru-RU")]
    [string]$Language,
    [switch]$WhatIf,
    [switch]$Diagnostic,
    [switch]$Force,
    [switch]$NoServiceRestart
)

# ============================================
# GLOBAL SCRIPT VARIABLES
# ============================================

# Configuration from settings.json
$Script:Config = $null
# Localization data (Messages, Prompts, ServiceNames)
$Script:Localization = $null
# Effective language (en-US / ru-RU)
$Script:LanguageEffective = "en-US"

# ============================================
# LOCALIZATION
# ============================================

function Get-1CLocalization {
    param(
        [string]$Language
    )

    $LocalizationPath = Join-Path $PSScriptRoot "Localization"
    $LocalizationFile = Join-Path $LocalizationPath "$Language.psd1"

    if (Test-Path $LocalizationFile) {
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "$Language.psd1"
    } else {
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "en-US.psd1"
    }
}

# ============================================
# SETTINGS LOAD AND INITIALIZATION
# ============================================

function Load-1CSettings {
    $ConfigPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $ConfigPath) {
        try {
            $json = Get-Content $ConfigPath -Raw -Encoding UTF8
            $Script:Config = $json | ConvertFrom-Json
        } catch {
            throw "Failed to read settings.json: $($_.Exception.Message)"
        }
    } else {
        # Minimal default configuration if settings.json is missing
        $Script:Config = [PSCustomObject]@{
            version  = "3.1.0"
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

    # Determine effective language
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
        throw "Script must be run as Administrator."
    }
}

# ============================================
# REGISTRY / 1C CONFIG DISCOVERY
# ============================================

function Get-1CAgentServiceInfo {
    # Try to discover 1C Agent service by DisplayName patterns.
    # Patterns may be extended or overridden via settings.json / localization if needed.
    $AgentPatterns = @(
        "1C:Enterprise 8.3 Server Agent*",
        "1C:Enterprise 8.3 Server Agent (x86-64)*",
        "1C:Enterprise 8.2 Server Agent*"
    )

    foreach ($Pattern in $AgentPatterns) {
        $Services = Get-Service -DisplayName $Pattern -ErrorAction SilentlyContinue
        if ($Services) {
            $Service = $Services[0]
            $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)"

            if (Test-Path $RegPath) {
                $RegProperties = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
                if ($RegProperties -and $RegProperties.ImagePath) {

                    # Parse ragent.exe parameters from ImagePath
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

                    $SrvInfoPath = $null
                    if ($Parameters.ContainsKey('d')) {
                        $SrvInfoPath = $Parameters['d']
                    }

                    # Try to detect version from path
                    $Version = $null
                    if ($RegProperties.ImagePath -match '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') {
                        $Version = $Matches[1]
                    }

                    return [PSCustomObject]@{
                        ServiceName = $Service.Name
                        DisplayName = $Service.DisplayName
                        ImagePath   = $RegProperties.ImagePath
                        Parameters  = $Parameters
                        SrvInfoPath = $SrvInfoPath
                        Version     = $Version
                    }
                }
            }
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

    if (Test-Path $ClusterRegPath) {
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
    }

    return $Nodes
}

function Get-1CFullConfiguration {
    $AgentService = Get-1CAgentServiceInfo

    $SrvInfoPath = if ($AgentService -and $AgentService.SrvInfoPath) {
        $AgentService.SrvInfoPath
    } elseif ($Script:Config -and $Script:Config.paths.defaultSrvInfo) {
        $Script:Config.paths.defaultSrvInfo
    } else {
        $null
    }

    $ClusterNodes = @()
    if ($SrvInfoPath) {
        $ClusterNodes = Get-1CClusterNodes -SrvInfoPath $SrvInfoPath
    }

    $Config = @{
        AgentService = $AgentService
        SrvInfoPath  = $SrvInfoPath
        ClusterNodes = $ClusterNodes
    }

    return [PSCustomObject]$Config
}

# ============================================
# LOGGING
# ============================================

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

    # Log retention
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
    $LogFile   = Join-Path $LogDir "1CCacheCleaner_$Timestamp.log"
    return $LogFile
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [string]$LogFile
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Formatted = "[$Timestamp] [$Level] $Message"

    # Determine minimal log level
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
    if (-not $Order.ContainsKey($levelKey)) {
        $levelKey = "INFO"
    }

    $minKey = if ($Order.ContainsKey($minLevel)) { $minLevel } else { "INFO" }

    if ($Order[$levelKey] -lt $Order[$minKey]) {
        return
    }

    # Console output
    $Colors = @{
        DEBUG   = "DarkGray"
        INFO    = "White"
        WARNING = "Yellow"
        ERROR   = "Red"
        SUCCESS = "Green"
    }

    $color = if ($Colors.ContainsKey($levelKey)) { $Colors[$levelKey] } else { "White" }
    Write-Host $Formatted -ForegroundColor $color

    # Log file output
    if ($LogFile) {
        $Formatted | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    # Event Log (only WARNING/ERROR and only if enabled in config)
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
            # EventLog errors must not break main logic
        }
    }
}

# ============================================
# SAFETY
# ============================================

function Test-Safety {
    param(
        [switch]$Force,
        [string]$LogFile
    )

    if ($Force) {
        if ($LogFile) {
            Write-Log -Message "Force parameter is set: safety checks are skipped." -Level "WARNING" -LogFile $LogFile
        }
        return $true
    }

    if ($Script:Config -and $Script:Config.safety -and -not $Script:Config.safety.checkActiveSessions) {
        if ($LogFile) {
            Write-Log -Message "Active 1C session check is disabled in settings.json." -Level "WARNING" -LogFile $LogFile
        }
        return $true
    }

    # Check active 1C processes
    $Processes1C = Get-Process -Name "1cv8", "1cv8c", "1cv8s" -ErrorAction SilentlyContinue
    if ($Processes1C) {
        $warningText = if ($Script:Localization -and $Script:Localization.Prompts.WarningActiveSessions) {
            $Script:Localization.Prompts.WarningActiveSessions
        } else {
            "WARNING: Active 1C processes found."
        }

        Write-Host $warningText -ForegroundColor Red -BackgroundColor Black
        $Processes1C | ForEach-Object {
            Write-Host ("  - {0} (PID: {1})" -f $_.ProcessName, $_.Id) -ForegroundColor Red
        }

        if ($LogFile) {
            Write-Log -Message "Active 1C processes detected; cache cleanup may be unsafe." -Level "ERROR" -LogFile $LogFile
        }

        if ($Script:Config.safety.requireConfirmation) {
            $prompt = if ($Script:Localization -and $Script:Localization.Prompts.ConfirmCleanup) {
                $Script:Localization.Prompts.ConfirmCleanup
            } else {
                "Proceed with cache cleanup? [Y/N]: "
            }

            $answer = Read-Host $prompt
            if ($answer -notin @("Y", "y", "Yes", "YES")) {
                if ($LogFile) {
                    Write-Log -Message "Cache cleanup cancelled by user due to active sessions." -Level "WARNING" -LogFile $LogFile
                }
                return $false
            }

            return $true
        } else {
            # If confirmation is disabled, require explicit Force
            return $false
        }
    }

    if ($LogFile -and $Script:Localization -and $Script:Localization.Messages.SafetyCheckPassed) {
        Write-Log -Message $Script:Localization.Messages.SafetyCheckPassed -Level "INFO" -LogFile $LogFile
    }

    return $true
}

# ============================================
# SERVICE CONTROL
# ============================================

function Stop-1CServices {
    param(
        [string[]]$ServiceNames,
        [int]$Timeout,
        [string]$LogFile,
        [switch]$WhatIf
    )

    $Stopped = @()

    foreach ($ServiceName in $ServiceNames) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $Service) {
            Write-Log -Message "Service not found: $ServiceName" -Level "WARNING" -LogFile $LogFile
            continue
        }

        if ($Service.Status -eq 'Stopped') {
            Write-Log -Message "Service already stopped: $ServiceName" -Level "INFO" -LogFile $LogFile
            $Stopped += $ServiceName
            continue
        }

        if ($WhatIf) {
            Write-Log -Message "[WhatIf] Would stop service: $ServiceName" -Level "INFO" -LogFile $LogFile
            $Stopped += $ServiceName
            continue
        }

        try {
            Write-Log -Message "Stopping service: $ServiceName" -Level "INFO" -LogFile $LogFile
            Stop-Service -Name $ServiceName -Force
            $Service.WaitForStatus('Stopped', (New-TimeSpan -Seconds $Timeout))
            Write-Log -Message "Service stopped: $ServiceName" -Level "SUCCESS" -LogFile $LogFile
            $Stopped += $ServiceName
        } catch {
            Write-Log -Message "Failed to stop service $ServiceName: $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
            throw
        }
    }

    Start-Sleep -Seconds 3
    return $Stopped
}

function Start-1CServices {
    param(
        [string[]]$ServiceNames,
        [string]$LogFile,
        [switch]$WhatIf
    )

    foreach ($ServiceName in $ServiceNames) {
        if ($WhatIf) {
            Write-Log -Message "[WhatIf] Would start service: $ServiceName" -Level "INFO" -LogFile $LogFile
            continue
        }

        try {
            Write-Log -Message "Starting service: $ServiceName" -Level "INFO" -LogFile $LogFile
            Start-Service -Name $ServiceName
            Start-Sleep -Seconds 5
            $Status = (Get-Service -Name $ServiceName).Status
            Write-Log -Message "Service started: $ServiceName (Status: $Status)" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to start service $ServiceName: $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

# ============================================
# CACHE CLEANUP
# ============================================

function Clear-1CCache {
    param(
        [string]$SrvInfoPath,
        [string]$LogFile,
        [switch]$WhatIf
    )

    Write-Log -Message "Starting cache cleanup: $SrvInfoPath" -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $SrvInfoPath)) {
        Write-Log -Message "Path not found: $SrvInfoPath" -Level "ERROR" -LogFile $LogFile
        throw "Path not found: $SrvInfoPath"
    }

    # Find cache directories snccntx*
    $CacheDirs = Get-ChildItem -Path $SrvInfoPath -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue

    if (-not $CacheDirs) {
        Write-Log -Message "No cache directories found under $SrvInfoPath" -Level "WARNING" -LogFile $LogFile
        return
    }

    $TotalDirs  = 0
    $TotalFiles = 0

    foreach ($Dir in $CacheDirs) {
        try {
            $Files = Get-ChildItem -Path $Dir.FullName -File -Recurse -ErrorAction SilentlyContinue
            $FileCount = $Files.Count

            if ($WhatIf) {
                Write-Log -Message "[WhatIf] Found cache directory: $($Dir.FullName) ($FileCount files)" -Level "INFO" -LogFile $LogFile
            } else {
                if ($FileCount -gt 0) {
                    $Files | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Cleaned: $($Dir.FullName) ($FileCount files)" -Level "INFO" -LogFile $LogFile
                    $TotalFiles += $FileCount
                }
            }

            $TotalDirs++
        } catch {
            Write-Log -Message "Error cleaning $($Dir.FullName): $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
        }
    }

    Write-Log -Message "Cache cleanup completed: $TotalDirs directories, $TotalFiles files" -Level "SUCCESS" -LogFile $LogFile
}

# ============================================
# DIAGNOSTICS
# ============================================

function Show-Diagnostics {
    $Config = Get-1CFullConfiguration

    Write-Host "=== 1C SERVER DIAGNOSTICS ===" -ForegroundColor Cyan
    Write-Host ""

    if ($Config.AgentService) {
        Write-Host "AGENT SERVICE:" -ForegroundColor Green
        Write-Host ("  Display name: {0}" -f $Config.AgentService.DisplayName) -ForegroundColor Yellow
        Write-Host ("  Version:      {0}" -f $Config.AgentService.Version) -ForegroundColor Gray
        $srvInfo = if ($Config.AgentService.SrvInfoPath) { $Config.AgentService.SrvInfoPath } else { "<not detected>" }
        Write-Host ("  SrvInfo path: {0}" -f $srvInfo) -ForegroundColor (if ($Config.AgentService.SrvInfoPath) { "Green" } else { "Red" })

        if ($Config.AgentService.Parameters.Count -gt 0) {
            Write-Host "  Parameters:" -ForegroundColor Gray
            foreach ($key in $Config.AgentService.Parameters.Keys) {
                Write-Host ("    -{0} : {1}" -f $key, $Config.AgentService.Parameters[$key]) -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "Agent service not found." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "CLUSTERS:" -ForegroundColor Green
    if ($Config.ClusterNodes.Count -gt 0) {
        foreach ($node in $Config.ClusterNodes) {
            Write-Host ("  Node: {0} (port: {1})" -f $node.NodeName, $node.AgentPort) -ForegroundColor Gray
            Write-Host ("    Reg file: {0}" -f $node.RegFile) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  Cluster information not found." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "SAFETY:" -ForegroundColor Green
    $Safe = Test-Safety
    $statusText = if ($Safe) { "NO active 1C processes" } else { "ACTIVE 1C processes detected" }
    Write-Host ("  Active sessions: {0}" -f $statusText) -ForegroundColor (if ($Safe) { "Green" } else { "Red" })

    Write-Host ""
    Write-Host "RECOMMENDED COMMAND:" -ForegroundColor Cyan
    $Cmd = ".\Clear-1CServerCache.ps1"
    if ($Config.SrvInfoPath) { $Cmd += " -SrvInfoPath `"$($Config.SrvInfoPath)`"" }
    if ($Script:LanguageEffective -eq "ru-RU") { $Cmd += " -Language ru-RU" }
    Write-Host ("  {0}" -f $Cmd) -ForegroundColor Yellow
}

# ============================================
# MAIN ENTRY POINT
# ============================================

function Main {
    # Require admin privileges
    Test-Admin

    # Load settings and localization
    Load-1CSettings

    if ($Diagnostic) {
        Show-Diagnostics
        return
    }

    # Initialize logging
    $LogFile = Initialize-Logging -Config $Script:Config

    # Start message
    if ($Script:Localization -and $Script:Localization.Messages.ScriptStarted) {
        Write-Log -Message ($Script:Localization.Messages.ScriptStarted -f $Script:Config.version) -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "1C Server Cache Cleaner started (version $($Script:Config.version))." -Level "INFO" -LogFile $LogFile
    }

    # Discover 1C configuration
    $Config = Get-1CFullConfiguration

    # Determine SrvInfoPath
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
        Write-Log -Message "SrvInfoPath could not be determined. Specify -SrvInfoPath or configure it in settings.json." -Level "ERROR" -LogFile $LogFile
        return
    }

    # Basic path sanity check: require directory path containing "srvinfo"
    if ($TargetPath -notmatch '\\srvinfo(\\|$)') {
        Write-Log -Message "SrvInfoPath looks unusual: $TargetPath" -Level "WARNING" -LogFile $LogFile
        if (-not $Force) {
            Write-Log -Message "Use -Force to work with non-standard SrvInfoPath." -Level "ERROR" -LogFile $LogFile
            return
        }
    }

    # Effective service stop timeout
    $EffectiveTimeout = if ($PSBoundParameters.ContainsKey("ServiceStopTimeout")) {
        $ServiceStopTimeout
    } elseif ($Script:Config.defaults.serviceStopTimeout) {
        [int]$Script:Config.defaults.serviceStopTimeout
    } else {
        120
    }

    # Service display names (from settings.json or localization)
    $ServiceDisplayAgent  = $null
    $ServiceDisplayServer = $null

    if ($Script:Config.serviceNames) {
        $ServiceDisplayAgent  = $Script:Config.serviceNames.agent[$Script:LanguageEffective]
        $ServiceDisplayServer = $Script:Config.serviceNames.server[$Script:LanguageEffective]
    }

    if (-not $ServiceDisplayAgent -and $Script:Localization.ServiceNames.Agent) {
        $ServiceDisplayAgent = $Script:Localization.ServiceNames.Agent
    }
    if (-not $ServiceDisplayServer -and $Script:Localization.ServiceNames.Server) {
        $ServiceDisplayServer = $Script:Localization.ServiceNames.Server
    }

    $ServicesToManage = @()
    if ($ServiceDisplayAgent)  { $ServicesToManage += $ServiceDisplayAgent }
    if ($ServiceDisplayServer) { $ServicesToManage += $ServiceDisplayServer }

    # Confirmation before cleanup if required by config
    if ($Script:Config.safety.requireConfirmation -and -not $Force) {
        $prompt = if ($Script:Localization.Prompts.ConfirmCleanup) {
            $Script:Localization.Prompts.ConfirmCleanup
        } else {
            "Proceed with cache cleanup? [Y/N]: "
        }

        $answer = Read-Host $prompt
        if ($answer -notin @("Y", "y", "Yes", "YES")) {
            Write-Log -Message "Cache cleanup cancelled by user before start." -Level "WARNING" -LogFile $LogFile
            return
        }
    }

    # Safety checks (active sessions etc.)
    if (-not (Test-Safety -Force:$Force -LogFile $LogFile)) {
        $failMsg = if ($Script:Localization.Messages.SafetyCheckFailed) {
            $Script:Localization.Messages.SafetyCheckFailed
        } else {
            "Safety check failed: active 1C processes or sessions detected."
        }
        Write-Log -Message $failMsg -Level "ERROR" -LogFile $LogFile
        Write-Host ""
        Write-Host $failMsg -ForegroundColor Red
        return
    }

    # Stop services if needed
    $StoppedServices = @()
    if (-not $NoServiceRestart -and $ServicesToManage.Count -gt 0) {
        Write-Log -Message "Stopping 1C services..." -Level "INFO" -LogFile $LogFile
        $StoppedServices = Stop-1CServices -ServiceNames $ServicesToManage -Timeout $EffectiveTimeout -LogFile $LogFile -WhatIf:$WhatIf
    } else {
        Write-Log -Message "Service stop is skipped (NoServiceRestart is set or no services defined)." -Level "INFO" -LogFile $LogFile
    }

    # Cache cleanup
    Clear-1CCache -SrvInfoPath $TargetPath -LogFile $LogFile -WhatIf:$WhatIf

    # Start services if they were stopped
    if (-not $NoServiceRestart -and $StoppedServices.Count -gt 0) {
        Write-Log -Message "Starting 1C services..." -Level "INFO" -LogFile $LogFile
        Start-1CServices -ServiceNames $StoppedServices -LogFile $LogFile -WhatIf:$WhatIf
    }

    # Completion message
    $completeMsg = if ($Script:Localization.Messages.Completion) {
        $Script:Localization.Messages.Completion
    } else {
        "Cache cleanup completed successfully."
    }

    Write-Log -Message $completeMsg -Level "SUCCESS" -LogFile $LogFile
    Write-Host ""
    Write-Host $completeMsg -ForegroundColor Green
    Write-Host ("Log file: {0}" -f $LogFile) -ForegroundColor Gray

    if ($WhatIf) {
        Write-Host ""
        Write-Host "This was a dry run (WhatIf mode)." -ForegroundColor Yellow
        Write-Host "Run without -WhatIf to perform actual cleanup." -ForegroundColor Yellow
    }
}

# ============================================
# SCRIPT START
# ============================================

try {
    Main
} catch {
    Write-Host ""
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run." -ForegroundColor Yellow
    exit 1
}
