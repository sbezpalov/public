<#
.SYNOPSIS
<<<<<<< HEAD
    Professional 1C server cache cleanup with automatic registry-based configuration detection.

.DESCRIPTION
    Version 3.1.0
    - Automatically discovers 1C server configuration from Windows registry (SrvInfoPath, version, etc.).
    - Supports clusters (reg_1cv8 analysis).
    - Uses settings.json for configuration (paths, logging, safety).
    - Uses localization (en-US / ru-RU) from psd1 files.
=======
    Профессиональная очистка кэша 1С сервера с автоматическим определением путей из реестра

.DESCRIPTION
    Версия 3.1.0
    - Автоматически находит параметры 1С из реестра Windows (SrvInfoPath, версия и т.п.)
    - Поддерживает кластеры (анализ reg_1cv8)
    - Использует settings.json для настроек (пути, логирование, безопасность)
    - Использует локализацию en-US / ru-RU через psd1
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375

.AUTHOR
    1C Server Automation Community

.VERSION
    3.1.0

.PARAMETER ServiceStopTimeout
<<<<<<< HEAD
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
=======
    Таймаут остановки служб в секундах (по умолчанию: из settings.json -> defaults.serviceStopTimeout)

.PARAMETER SrvInfoPath
    Ручное указание пути к srvinfo (если не определяется автоматически или если нужно переопределить)

.PARAMETER Language
    Язык интерфейса: en-US или ru-RU.
    Если параметр не указан, используется defaults.language из settings.json:
        - "auto"  → язык текущей культуры системы
        - "en-US"/"ru-RU" → принудительно указанный язык

.PARAMETER WhatIf
    Пробный запуск, без реальной остановки служб и удаления файлов

.PARAMETER Diagnostic
    Диагностический режим: выводит информацию о конфигурации 1С (без очистки)

.PARAMETER Force
    Пропуск проверок безопасности (активные сессии и проверки пути)
    ВНИМАНИЕ: использовать только осознанно

.PARAMETER NoServiceRestart
    Не останавливать и не запускать службы 1С (очистка при работающих службах не рекомендуется)

.EXAMPLE
    .\Clear-1CServerCache.ps1
    Стандартная очистка с настройками из settings.json

.EXAMPLE
    .\Clear-1CServerCache.ps1 -SrvInfoPath "C:\Program Files\1cv8\srvinfo"
    Очистка с явно указанным каталогом srvinfo

.EXAMPLE
    .\Clear-1CServerCache.ps1 -WhatIf
    Пробный запуск без фактической очистки
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375

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
<<<<<<< HEAD
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
=======
# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ СКРИПТА
# ============================================

# Конфигурация из settings.json
$Script:Config = $null
# Локализация (Messages/Prompts/ServiceNames)
$Script:Localization = $null
# Эффективный язык (en-US/ru-RU)
$Script:LanguageEffective = "en-US"

# ============================================
# ЛОКАЛИЗАЦИЯ
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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
        # Фолбэк на en-US
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "en-US.psd1"
    }
}

# ============================================
<<<<<<< HEAD
# SETTINGS LOAD AND INITIALIZATION
=======
# ЗАГРУЗКА НАСТРОЕК И ИНИЦИАЛИЗАЦИЯ
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
# ============================================

function Load-1CSettings {
    $ConfigPath = Join-Path $PSScriptRoot "settings.json"

    if (Test-Path $ConfigPath) {
        try {
            $json = Get-Content $ConfigPath -Raw -Encoding UTF8
            $Script:Config = $json | ConvertFrom-Json
        } catch {
<<<<<<< HEAD
            throw "Failed to read settings.json: $($_.Exception.Message)"
        }
    } else {
        # Minimal default configuration if settings.json is missing
=======
            throw "Не удалось прочитать settings.json: $($_.Exception.Message)"
        }
    } else {
        # Базовые дефолты, если settings.json отсутствует
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
    # Determine effective language
=======
    # Определение языка
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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
<<<<<<< HEAD
        throw "Script must be run as Administrator."
=======
        throw "Скрипт должен быть запущен от имени администратора."
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    }
}

# ============================================
<<<<<<< HEAD
# REGISTRY / 1C CONFIG DISCOVERY
# ============================================

function Get-1CAgentServiceInfo {
    # Try to discover 1C Agent service by DisplayName patterns.
    # Patterns may be extended or overridden via settings.json / localization if needed.
=======
# РАБОТА С РЕЕСТРОМ / КОНФИГУРАЦИЕЙ 1С
# ============================================

function Get-1CAgentServiceInfo {
    # Поиск службы агента 1С в системных службах
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
                    # Try to detect version from path
=======
                    # Определение версии из каталога ragent.exe
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
    # Log retention
=======
    # Ротация логов
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
    # Determine minimal log level
=======
    # Определение минимального уровня логирования
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
    # Console output
=======
    # Консоль
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    $Colors = @{
        DEBUG   = "DarkGray"
        INFO    = "White"
        WARNING = "Yellow"
        ERROR   = "Red"
        SUCCESS = "Green"
    }

    $color = if ($Colors.ContainsKey($levelKey)) { $Colors[$levelKey] } else { "White" }
    Write-Host $Formatted -ForegroundColor $color

<<<<<<< HEAD
    # Log file output
=======
    # Файл
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    if ($LogFile) {
        $Formatted | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

<<<<<<< HEAD
    # Event Log (only WARNING/ERROR and only if enabled in config)
=======
    # Event Log (только для WARNING/ERROR и только если включено в настройках)
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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
<<<<<<< HEAD
            # EventLog errors must not break main logic
=======
            # Ошибки логирования в EventLog не должны ломать основной сценарий
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }
    }
}

# ============================================
<<<<<<< HEAD
# SAFETY
=======
# БЕЗОПАСНОСТЬ
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
# ============================================

function Test-Safety {
    param(
        [switch]$Force,
        [string]$LogFile
    )

    if ($Force) {
        if ($LogFile) {
<<<<<<< HEAD
            Write-Log -Message "Force parameter is set: safety checks are skipped." -Level "WARNING" -LogFile $LogFile
=======
            Write-Log -Message "Параметр -Force указан: проверки безопасности пропущены" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }
        return $true
    }

    if ($Script:Config -and $Script:Config.safety -and -not $Script:Config.safety.checkActiveSessions) {
        if ($LogFile) {
<<<<<<< HEAD
            Write-Log -Message "Active 1C session check is disabled in settings.json." -Level "WARNING" -LogFile $LogFile
=======
            Write-Log -Message "Проверка активных сессий 1С отключена в settings.json" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }
        return $true
    }

<<<<<<< HEAD
    # Check active 1C processes
=======
    # Проверка активных процессов 1С
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    $Processes1C = Get-Process -Name "1cv8", "1cv8c", "1cv8s" -ErrorAction SilentlyContinue
    if ($Processes1C) {
        $warningText = if ($Script:Localization -and $Script:Localization.Prompts.WarningActiveSessions) {
            $Script:Localization.Prompts.WarningActiveSessions
        } else {
<<<<<<< HEAD
            "WARNING: Active 1C processes found."
=======
            "ВНИМАНИЕ: Найдены активные процессы 1С"
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }

        Write-Host $warningText -ForegroundColor Red -BackgroundColor Black
        $Processes1C | ForEach-Object {
            Write-Host ("  - {0} (PID: {1})" -f $_.ProcessName, $_.Id) -ForegroundColor Red
        }

        if ($LogFile) {
<<<<<<< HEAD
            Write-Log -Message "Active 1C processes detected; cache cleanup may be unsafe." -Level "ERROR" -LogFile $LogFile
=======
            Write-Log -Message "Обнаружены активные процессы 1С, очистка потенциально опасна" -Level "ERROR" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }

        if ($Script:Config.safety.requireConfirmation) {
            $prompt = if ($Script:Localization -and $Script:Localization.Prompts.ConfirmCleanup) {
                $Script:Localization.Prompts.ConfirmCleanup
            } else {
                "Proceed with cache cleanup? [Y/N]: "
            }

            $answer = Read-Host $prompt
<<<<<<< HEAD
            if ($answer -notin @("Y", "y", "Yes", "YES")) {
                if ($LogFile) {
                    Write-Log -Message "Cache cleanup cancelled by user due to active sessions." -Level "WARNING" -LogFile $LogFile
=======
            if ($answer -notin @("Y", "y", "Yes", "YES", "Д", "д", "Да", "ДА")) {
                if ($LogFile) {
                    Write-Log -Message "Очистка кэша отменена пользователем из-за активных сессий" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
                }
                return $false
            }

            return $true
        } else {
<<<<<<< HEAD
            # If confirmation is disabled, require explicit Force
=======
            # Требуем явного применения -Force, если confirmation отключен
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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
<<<<<<< HEAD
            Write-Log -Message "Service not found: $ServiceName" -Level "WARNING" -LogFile $LogFile
=======
            Write-Log -Message "Служба не найдена: $ServiceName" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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

<<<<<<< HEAD
    Write-Log -Message "Starting cache cleanup: $SrvInfoPath" -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $SrvInfoPath)) {
        Write-Log -Message "Path not found: $SrvInfoPath" -Level "ERROR" -LogFile $LogFile
        throw "Path not found: $SrvInfoPath"
    }

    # Find cache directories snccntx*
    $CacheDirs = Get-ChildItem -Path $SrvInfoPath -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue

    if (-not $CacheDirs) {
        Write-Log -Message "No cache directories found under $SrvInfoPath" -Level "WARNING" -LogFile $LogFile
=======
    Write-Log -Message "Начинаем очистку кэша: $SrvInfoPath" -Level "INFO" -LogFile $LogFile

    if (-not (Test-Path $SrvInfoPath)) {
        Write-Log -Message "Путь не найден: $SrvInfoPath" -Level "ERROR" -LogFile $LogFile
        throw "Path not found: $SrvInfoPath"
    }

    # Поиск директорий кэша snccntx*
    $CacheDirs = Get-ChildItem -Path $SrvInfoPath -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue

    if (-not $CacheDirs) {
        Write-Log -Message "Директории кэша не найдены под $SrvInfoPath" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        return
    }

    $TotalDirs  = 0
    $TotalFiles = 0

    foreach ($Dir in $CacheDirs) {
        try {
            $Files = Get-ChildItem -Path $Dir.FullName -File -Recurse -ErrorAction SilentlyContinue
            $FileCount = $Files.Count

            if ($WhatIf) {
<<<<<<< HEAD
                Write-Log -Message "[WhatIf] Found cache directory: $($Dir.FullName) ($FileCount files)" -Level "INFO" -LogFile $LogFile
            } else {
                if ($FileCount -gt 0) {
                    $Files | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Cleaned: $($Dir.FullName) ($FileCount files)" -Level "INFO" -LogFile $LogFile
=======
                Write-Log -Message "[WhatIf] Нашли кэш: $($Dir.FullName) ($FileCount файлов)" -Level "INFO" -LogFile $LogFile
            } else {
                if ($FileCount -gt 0) {
                    $Files | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Очищено: $($Dir.FullName) ($FileCount файлов)" -Level "INFO" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
                    $TotalFiles += $FileCount
                }
            }

            $TotalDirs++
        } catch {
            Write-Log -Message "Error cleaning $($Dir.FullName): $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
        }
    }

<<<<<<< HEAD
    Write-Log -Message "Cache cleanup completed: $TotalDirs directories, $TotalFiles files" -Level "SUCCESS" -LogFile $LogFile
=======
    Write-Log -Message "Очистка завершена: $TotalDirs директорий, $TotalFiles файлов" -Level "SUCCESS" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
}

# ============================================
# DIAGNOSTICS
# ============================================

function Show-Diagnostics {
    $Config = Get-1CFullConfiguration

<<<<<<< HEAD
    Write-Host "=== 1C SERVER DIAGNOSTICS ===" -ForegroundColor Cyan
    Write-Host ""

    if ($Config.AgentService) {
        Write-Host "AGENT SERVICE:" -ForegroundColor Green
        Write-Host ("  Display name: {0}" -f $Config.AgentService.DisplayName) -ForegroundColor Yellow
        Write-Host ("  Version:      {0}" -f $Config.AgentService.Version) -ForegroundColor Gray
        $srvInfo = if ($Config.AgentService.SrvInfoPath) { $Config.AgentService.SrvInfoPath } else { "<not detected>" }
        Write-Host ("  SrvInfo path: {0}" -f $srvInfo) -ForegroundColor (if ($Config.AgentService.SrvInfoPath) { "Green" } else { "Red" })
=======
    Write-Host "=== ДИАГНОСТИКА 1С СЕРВЕРА ===" -ForegroundColor Cyan
    Write-Host ""

    if ($Config.AgentService) {
        Write-Host "СЛУЖБА АГЕНТА:" -ForegroundColor Green
        Write-Host ("  Имя: {0}" -f $Config.AgentService.DisplayName) -ForegroundColor Yellow
        Write-Host ("  Версия: {0}" -f $Config.AgentService.Version) -ForegroundColor Gray
        $srvInfo = if ($Config.AgentService.SrvInfoPath) { $Config.AgentService.SrvInfoPath } else { "<не определён>" }
        Write-Host ("  Путь srvinfo: {0}" -f $srvInfo) -ForegroundColor (if ($Config.AgentService.SrvInfoPath) { "Green" } else { "Red" })
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375

        if ($Config.AgentService.Parameters.Count -gt 0) {
            Write-Host "  Parameters:" -ForegroundColor Gray
            foreach ($key in $Config.AgentService.Parameters.Keys) {
                Write-Host ("    -{0} : {1}" -f $key, $Config.AgentService.Parameters[$key]) -ForegroundColor Gray
            }
        }
    } else {
<<<<<<< HEAD
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
=======
        Write-Host "Служба агента 1С не найдена." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "КЛАСТЕРЫ:" -ForegroundColor Green
    if ($Config.ClusterNodes.Count -gt 0) {
        foreach ($node in $Config.ClusterNodes) {
            Write-Host ("  Узел: {0} (порт: {1})" -f $node.NodeName, $node.AgentPort) -ForegroundColor Gray
            Write-Host ("    Reg-файл: {0}" -f $node.RegFile) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  Информация о кластерах не найдена." -ForegroundColor DarkGray
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    }

    Write-Host ""
    Write-Host "SAFETY:" -ForegroundColor Green
    $Safe = Test-Safety
<<<<<<< HEAD
    $statusText = if ($Safe) { "NO active 1C processes" } else { "ACTIVE 1C processes detected" }
    Write-Host ("  Active sessions: {0}" -f $statusText) -ForegroundColor (if ($Safe) { "Green" } else { "Red" })
=======
    $statusText = if ($Safe) { "НЕТ активных процессов 1С ✅" } else { "ОБНАРУЖЕНЫ активные процессы 1С ⚠️" }
    Write-Host ("  Активные сессии: {0}" -f $statusText) -ForegroundColor (if ($Safe) { "Green" } else { "Red" })
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375

    Write-Host ""
    Write-Host "RECOMMENDED COMMAND:" -ForegroundColor Cyan
    $Cmd = ".\Clear-1CServerCache.ps1"
    if ($Config.SrvInfoPath) { $Cmd += " -SrvInfoPath `"$($Config.SrvInfoPath)`"" }
    if ($Script:LanguageEffective -eq "ru-RU") { $Cmd += " -Language ru-RU" }
    Write-Host ("  {0}" -f $Cmd) -ForegroundColor Yellow
}

# ============================================
<<<<<<< HEAD
# MAIN ENTRY POINT
# ============================================

function Main {
    # Require admin privileges
    Test-Admin

    # Load settings and localization
=======
# ОСНОВНОЙ ВХОД
# ============================================

function Main {
    # Проверка прав администратора
    Test-Admin

    # Загрузка настроек и локализации
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    Load-1CSettings

    if ($Diagnostic) {
        Show-Diagnostics
        return
    }

<<<<<<< HEAD
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
=======
    # Инициализация логирования
    $LogFile = Initialize-Logging -Config $Script:Config

    # Стартовое сообщение
    if ($Script:Localization -and $Script:Localization.Messages.ScriptStarted) {
        Write-Log -Message ($Script:Localization.Messages.ScriptStarted -f $Script:Config.version) -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "1C Server Cache Cleaner started (version $($Script:Config.version))" -Level "INFO" -LogFile $LogFile
    }

    # Чтение конфигурации 1С
    $Config = Get-1CFullConfiguration

    # Определение SrvInfoPath
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
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
<<<<<<< HEAD
        Write-Log -Message "SrvInfoPath could not be determined. Specify -SrvInfoPath or configure it in settings.json." -Level "ERROR" -LogFile $LogFile
        return
    }

    # Basic path sanity check: require directory path containing "srvinfo"
    if ($TargetPath -notmatch '\\srvinfo(\\|$)') {
        Write-Log -Message "SrvInfoPath looks unusual: $TargetPath" -Level "WARNING" -LogFile $LogFile
        if (-not $Force) {
            Write-Log -Message "Use -Force to work with non-standard SrvInfoPath." -Level "ERROR" -LogFile $LogFile
=======
        Write-Log -Message "Не удалось определить SrvInfoPath. Укажите его параметром -SrvInfoPath или в settings.json" -Level "ERROR" -LogFile $LogFile
        return
    }

    # Базовая проверка пути: должны работать под каталогом, содержащим 'srvinfo'
    if ($TargetPath -notmatch '\\srvinfo(\\|$)') {
        Write-Log -Message "Путь SrvInfoPath выглядит нетипично: $TargetPath" -Level "WARNING" -LogFile $LogFile
        if (-not $Force) {
            Write-Log -Message "Для работы с нетипичным путём используйте параметр -Force" -Level "ERROR" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
            return
        }
    }

<<<<<<< HEAD
    # Effective service stop timeout
=======
    # Итоговый таймаут остановки служб
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    $EffectiveTimeout = if ($PSBoundParameters.ContainsKey("ServiceStopTimeout")) {
        $ServiceStopTimeout
    } elseif ($Script:Config.defaults.serviceStopTimeout) {
        [int]$Script:Config.defaults.serviceStopTimeout
    } else {
        120
    }

<<<<<<< HEAD
    # Service display names (from settings.json or localization)
    $ServiceDisplayAgent  = $null
    $ServiceDisplayServer = $null

    if ($Script:Config.serviceNames) {
        $ServiceDisplayAgent  = $Script:Config.serviceNames.agent[$Script:LanguageEffective]
=======
    # Сервисные имена (из settings.json или локализации)
    $ServiceDisplayAgent = $null
    $ServiceDisplayServer = $null

    if ($Script:Config.serviceNames) {
        $ServiceDisplayAgent = $Script:Config.serviceNames.agent[$Script:LanguageEffective]
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        $ServiceDisplayServer = $Script:Config.serviceNames.server[$Script:LanguageEffective]
    }

    if (-not $ServiceDisplayAgent -and $Script:Localization.ServiceNames.Agent) {
        $ServiceDisplayAgent = $Script:Localization.ServiceNames.Agent
    }
    if (-not $ServiceDisplayServer -and $Script:Localization.ServiceNames.Server) {
        $ServiceDisplayServer = $Script:Localization.ServiceNames.Server
    }

    $ServicesToManage = @()
<<<<<<< HEAD
    if ($ServiceDisplayAgent)  { $ServicesToManage += $ServiceDisplayAgent }
    if ($ServiceDisplayServer) { $ServicesToManage += $ServiceDisplayServer }

    # Confirmation before cleanup if required by config
=======
    if ($ServiceDisplayAgent) { $ServicesToManage += $ServiceDisplayAgent }
    if ($ServiceDisplayServer) { $ServicesToManage += $ServiceDisplayServer }

    # Дополнительное подтверждение перед очисткой, если включено в настройках
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    if ($Script:Config.safety.requireConfirmation -and -not $Force) {
        $prompt = if ($Script:Localization.Prompts.ConfirmCleanup) {
            $Script:Localization.Prompts.ConfirmCleanup
        } else {
            "Proceed with cache cleanup? [Y/N]: "
        }

        $answer = Read-Host $prompt
<<<<<<< HEAD
        if ($answer -notin @("Y", "y", "Yes", "YES")) {
            Write-Log -Message "Cache cleanup cancelled by user before start." -Level "WARNING" -LogFile $LogFile
=======
        if ($answer -notin @("Y", "y", "Yes", "YES", "Д", "д", "Да", "ДА")) {
            Write-Log -Message "Очистка кэша отменена пользователем до начала операции" -Level "WARNING" -LogFile $LogFile
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
            return
        }
    }

<<<<<<< HEAD
    # Safety checks (active sessions etc.)
=======
    # Проверка безопасности (активные сессии и пр.)
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    if (-not (Test-Safety -Force:$Force -LogFile $LogFile)) {
        $failMsg = if ($Script:Localization.Messages.SafetyCheckFailed) {
            $Script:Localization.Messages.SafetyCheckFailed
        } else {
<<<<<<< HEAD
            "Safety check failed: active 1C processes or sessions detected."
=======
            "Безопасность: обнаружены активные сессии/процессы 1С"
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
        }
        Write-Log -Message $failMsg -Level "ERROR" -LogFile $LogFile
        Write-Host ""
        Write-Host $failMsg -ForegroundColor Red
        return
    }

<<<<<<< HEAD
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
=======
    # Остановка служб
    $StoppedServices = @()
    if (-not $NoServiceRestart -and $ServicesToManage.Count -gt 0) {
        Write-Log -Message "Останавливаем службы 1С..." -Level "INFO" -LogFile $LogFile
        $StoppedServices = Stop-1CServices -ServiceNames $ServicesToManage -Timeout $EffectiveTimeout -LogFile $LogFile -WhatIf:$WhatIf
    } else {
        Write-Log -Message "Остановка служб пропущена (NoServiceRestart или не определены имена служб)" -Level "INFO" -LogFile $LogFile
    }

    # Очистка кэша
    Clear-1CCache -SrvInfoPath $TargetPath -LogFile $LogFile -WhatIf:$WhatIf

    # Запуск служб
    if (-not $NoServiceRestart -and $StoppedServices.Count -gt 0) {
        Write-Log -Message "Запускаем службы 1С..." -Level "INFO" -LogFile $LogFile
        Start-1CServices -ServiceNames $StoppedServices -LogFile $LogFile -WhatIf:$WhatIf
    }

    # Завершение
    $completeMsg = if ($Script:Localization.Messages.Completion) {
        $Script:Localization.Messages.Completion
    } else {
        "Очистка кэша успешно завершена"
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    }

    Write-Log -Message $completeMsg -Level "SUCCESS" -LogFile $LogFile
    Write-Host ""
<<<<<<< HEAD
    Write-Host $completeMsg -ForegroundColor Green
    Write-Host ("Log file: {0}" -f $LogFile) -ForegroundColor Gray

    if ($WhatIf) {
        Write-Host ""
        Write-Host "This was a dry run (WhatIf mode)." -ForegroundColor Yellow
        Write-Host "Run without -WhatIf to perform actual cleanup." -ForegroundColor Yellow
=======
    Write-Host "✅ $completeMsg" -ForegroundColor Green
    Write-Host ("Лог сохранён: {0}" -f $LogFile) -ForegroundColor Gray

    if ($WhatIf) {
        Write-Host ""
        Write-Host "⚠ Это был пробный запуск (WhatIf)" -ForegroundColor Yellow
        Write-Host "   Для реальной очистки запустите без параметра -WhatIf" -ForegroundColor Yellow
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    }
}

# ============================================
<<<<<<< HEAD
# SCRIPT START
=======
# ЗАПУСК
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
# ============================================

try {
    Main
} catch {
    Write-Host ""
<<<<<<< HEAD
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run." -ForegroundColor Yellow
=======
    Write-Host ("❌ ОШИБКА: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "Подсказка: Используйте -Diagnostic для диагностики или -WhatIf для пробного запуска" -ForegroundColor Yellow
>>>>>>> da61935b5a1e37e9028552d2d47e7dcbbb71f375
    exit 1
}
