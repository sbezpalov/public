<#
.SYNOPSIS
    Профессиональная очистка кэша 1С сервера с автоматическим определением путей из реестра
.DESCRIPTION
    Версия 3.0.0 - Минималистичная версия с поддержкой EN/RU языков
    Автоматически находит параметры 1С из реестра Windows, поддерживает кластеры
.AUTHOR
    1C Server Automation Community
.VERSION
    3.0.0
.PARAMETER ServiceStopTimeout
    Таймаут остановки служб в секундах (по умолчанию: 120)
.PARAMETER SrvInfoPath
    Ручное указание пути к srvinfo (если не определяется автоматически)
.PARAMETER Language
    Язык интерфейса: en-US (по умолчанию) или ru-RU
.PARAMETER WhatIf
    Пробный запуск без выполнения действий
.PARAMETER Diagnostic
    Режим диагностики - показывает конфигурацию без очистки
.PARAMETER Force
    Принудительный режим (игнорирует проверки безопасности)
.PARAMETER NoServiceRestart
    Не перезапускать службы (только очистка кэша)
.EXAMPLE
    .\Clear-1CServerCache.ps1 -Diagnostic
    Показать текущую конфигурацию 1С
.EXAMPLE
    .\Clear-1CServerCache.ps1 -WhatIf -Verbose
    Пробный запуск с детальным выводом
.EXAMPLE
    .\Clear-1CServerCache.ps1 -Language ru-RU
    Очистка с русским интерфейсом
#>

[CmdletBinding(SupportsShouldProcess=$true)]
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
# РЕГИОНАЛЬНЫЕ НАСТРОЙКИ И ЛОКАЛИЗАЦИЯ
# ============================================

# Загрузка локализации
function Get-1CLocalization {
    param([string]$Language)
    
    $LocalizationPath = Join-Path $PSScriptRoot "Localization"
    $LocalizationFile = Join-Path $LocalizationPath "$Language.psd1"
    
    if (Test-Path $LocalizationFile) {
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "$Language.psd1"
    } else {
        return Import-LocalizedData -BaseDirectory $LocalizationPath -FileName "en-US.psd1"
    }
}

# Определяем язык по умолчанию
if (-not $Language) {
    $Language = (Get-Culture).Name
    if ($Language -notin @("en-US", "ru-RU")) { $Language = "en-US" }
}

$Localization = Get-1CLocalization -Language $Language

# ============================================
# ЧТЕНИЕ РЕЕСТРА WINDOWS
# ============================================

function Get-1CAgentServiceInfo {
    # Поиск службы агента 1С в реестре
    $AgentPatterns = @(
        "1C:Enterprise 8.3 Server Agent*",
        "Агент сервера 1С:Предприятие*",
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
                    # Парсинг параметров из ImagePath
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
                    
                    # Извлечение информации
                    $SrvInfoPath = if ($Parameters.d) { $Parameters.d } else { $null }
                    $Version = if ($RegProperties.ImagePath -match '1cv8\\([\d\.]+)\\bin') { $Matches[1] } else { $null }
                    
                    return [PSCustomObject]@{
                        ServiceName = $Service.Name
                        DisplayName = $Service.DisplayName
                        ImagePath = $RegProperties.ImagePath
                        Parameters = $Parameters
                        SrvInfoPath = $SrvInfoPath
                        Version = $Version
                    }
                }
            }
        }
    }
    
    return $null
}

function Get-1CClusterNodes {
    param([string]$SrvInfoPath)
    
    $Nodes = @()
    $ClusterRegPath = Join-Path $SrvInfoPath "reg_1cv8"
    
    if (Test-Path $ClusterRegPath) {
        $RegFiles = Get-ChildItem -Path $ClusterRegPath -Filter "*.reg" -ErrorAction SilentlyContinue
        foreach ($RegFile in $RegFiles) {
            $Content = Get-Content $RegFile.FullName -Raw -ErrorAction SilentlyContinue
            if ($Content -match '"AgentHost"="([^"]+)"') {
                $NodeInfo = @{
                    NodeName = $Matches[1]
                    RegFile = $RegFile.FullName
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
    $Config = @{
        AgentService = $AgentService
        SrvInfoPath = if ($AgentService -and $AgentService.SrvInfoPath) { $AgentService.SrvInfoPath } else { $null }
        ClusterNodes = if ($AgentService -and $AgentService.SrvInfoPath) { Get-1CClusterNodes -SrvInfoPath $AgentService.SrvInfoPath } else { @() }
    }
    
    return [PSCustomObject]$Config
}

# ============================================
# ЛОГИРОВАНИЕ
# ============================================

function Initialize-Logging {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogDir = "C:\Scripts\Logs\1C_Maintenance"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    
    $LogFile = Join-Path $LogDir "1CCacheCleaner_$Timestamp.log"
    return $LogFile
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO", [string]$LogFile)
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Formatted = "[$Timestamp] [$Level] $Message"
    
    # Консоль
    $Colors = @{INFO="White"; WARNING="Yellow"; ERROR="Red"; SUCCESS="Green"}
    Write-Host $Formatted -ForegroundColor $Colors[$Level]
    
    # Файл
    $Formatted | Out-File -FilePath $LogFile -Append -Encoding UTF8
    
    # Event Log (только для важных событий)
    if ($Level -in @("ERROR", "WARNING")) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("1C Cache Cleaner")) {
                [System.Diagnostics.EventLog]::CreateEventSource("1C Cache Cleaner", "Application")
            }
            $EventId = switch ($Level) { "ERROR" { 1001 }; "WARNING" { 1002 }; default { 1000 } }
            Write-EventLog -LogName "Application" -Source "1C Cache Cleaner" -EventId $EventId -EntryType $Level -Message $Message
        } catch { }
    }
}

# ============================================
# БЕЗОПАСНОСТЬ И ПРОВЕРКИ
# ============================================

function Test-Safety {
    # Проверка активных сессий 1С
    $1CProcesses = Get-Process -Name "1cv8", "1cv8c", "1cv8s" -ErrorAction SilentlyContinue
    if ($1CProcesses) {
        Write-Host "НАЙДЕНЫ АКТИВНЫЕ СЕССИИ 1С!" -ForegroundColor Red -BackgroundColor Black
        $1CProcesses | ForEach-Object { Write-Host "  - $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Red }
        return $false
    }
    return $true
}

# ============================================
# УПРАВЛЕНИЕ СЛУЖБАМИ
# ============================================

function Stop-1CServices {
    param([string[]]$ServiceNames, [int]$Timeout, [string]$LogFile, [switch]$WhatIf)
    
    $Stopped = @()
    foreach ($ServiceName in $ServiceNames) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $Service) { 
            Write-Log -Message "Служба не найдена: $ServiceName" -Level "WARNING" -LogFile $LogFile
            continue 
        }
        
        if ($Service.Status -eq 'Stopped') {
            Write-Log -Message "Служба уже остановлена: $ServiceName" -Level "INFO" -LogFile $LogFile
            $Stopped += $ServiceName
            continue
        }
        
        if ($WhatIf) {
            Write-Log -Message "[WhatIf] Остановка службы: $ServiceName" -Level "INFO" -LogFile $LogFile
            $Stopped += $ServiceName
            continue
        }
        
        try {
            Write-Log -Message "Останавливаем службу: $ServiceName" -Level "INFO" -LogFile $LogFile
            Stop-Service -Name $ServiceName -Force
            $Service.WaitForStatus('Stopped', (New-TimeSpan -Seconds $Timeout))
            Write-Log -Message "Служба остановлена: $ServiceName" -Level "SUCCESS" -LogFile $LogFile
            $Stopped += $ServiceName
        } catch {
            Write-Log -Message "Ошибка остановки службы $ServiceName : $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
    
    Start-Sleep -Seconds 3
    return $Stopped
}

function Start-1CServices {
    param([string[]]$ServiceNames, [string]$LogFile, [switch]$WhatIf)
    
    foreach ($ServiceName in $ServiceNames) {
        if ($WhatIf) {
            Write-Log -Message "[WhatIf] Запуск службы: $ServiceName" -Level "INFO" -LogFile $LogFile
            continue
        }
        
        try {
            Write-Log -Message "Запускаем службу: $ServiceName" -Level "INFO" -LogFile $LogFile
            Start-Service -Name $ServiceName
            Start-Sleep -Seconds 5
            $Status = (Get-Service -Name $ServiceName).Status
            Write-Log -Message "Служба запущена: $ServiceName (Статус: $Status)" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Ошибка запуска службы $ServiceName : $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
            throw
        }
    }
}

# ============================================
# ОЧИСТКА КЭША
# ============================================

function Clear-1CCache {
    param([string]$SrvInfoPath, [string]$LogFile, [switch]$WhatIf)
    
    Write-Log -Message "Начинаем очистку кэша: $SrvInfoPath" -Level "INFO" -LogFile $LogFile
    
    # Проверка пути
    if (-not (Test-Path $SrvInfoPath)) {
        Write-Log -Message "Путь не найден: $SrvInfoPath" -Level "ERROR" -LogFile $LogFile
        throw "Path not found"
    }
    
    # Поиск директорий кэша
    $CacheDirs = Get-ChildItem -Path $SrvInfoPath -Directory -Filter "snccntx*" -Recurse -ErrorAction SilentlyContinue
    
    if (-not $CacheDirs) {
        Write-Log -Message "Директории кэша не найдены" -Level "WARNING" -LogFile $LogFile
        return
    }
    
    Write-Log -Message "Найдено директорий кэша: $($CacheDirs.Count)" -Level "INFO" -LogFile $LogFile
    $TotalFiles = 0
    $TotalDirs = 0
    
    foreach ($Dir in $CacheDirs) {
        if ($WhatIf) {
            $Files = Get-ChildItem -Path $Dir.FullName -File -ErrorAction SilentlyContinue
            $FileCount = if ($Files) { $Files.Count } else { 0 }
            Write-Log -Message "[WhatIf] Будет очищено: $($Dir.FullName) ($FileCount файлов)" -Level "INFO" -LogFile $LogFile
            continue
        }
        
        try {
            $Files = Get-ChildItem -Path $Dir.FullName -File -ErrorAction SilentlyContinue
            $FileCount = if ($Files) { $Files.Count } else { 0 }
            
            if ($FileCount -gt 0) {
                $Files | Remove-Item -Force
                Write-Log -Message "Очищено: $($Dir.Name) ($FileCount файлов)" -Level "INFO" -LogFile $LogFile
                $TotalFiles += $FileCount
            }
            
            $TotalDirs++
        } catch {
            Write-Log -Message "Ошибка очистки $($Dir.FullName): $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
        }
    }
    
    Write-Log -Message "Очистка завершена: $TotalDirs директорий, $TotalFiles файлов" -Level "SUCCESS" -LogFile $LogFile
}

# ============================================
# ДИАГНОСТИКА
# ============================================

function Show-Diagnostics {
    $Config = Get-1CFullConfiguration
    
    Write-Host "=== ДИАГНОСТИКА 1С СЕРВЕРА ===" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Config.AgentService) {
        Write-Host "СЛУЖБА АГЕНТА:" -ForegroundColor Green
        Write-Host "  Имя: $($Config.AgentService.DisplayName)" -ForegroundColor Yellow
        Write-Host "  Версия: $($Config.AgentService.Version)" -ForegroundColor Gray
        Write-Host "  Путь srvinfo: $(if ($Config.AgentService.SrvInfoPath) { $Config.AgentService.SrvInfoPath } else { 'Не найден' })" -ForegroundColor $(if ($Config.AgentService.SrvInfoPath) { "Green" } else { "Red" })
        
        if ($Config.AgentService.Parameters.Count -gt 0) {
            Write-Host "  Параметры:" -ForegroundColor Gray
            foreach ($key in $Config.AgentService.Parameters.Keys) {
                Write-Host "    -$key : $($Config.AgentService.Parameters[$key])" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "СЛУЖБА АГЕНТА: Не найдена!" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "ПУТИ:" -ForegroundColor Green
    Write-Host "  Основной путь: $(if ($Config.SrvInfoPath) { $Config.SrvInfoPath } else { 'Не определен' })" -ForegroundColor $(if ($Config.SrvInfoPath) { "Green" } else { "Yellow" })
    
    if ($Config.SrvInfoPath -and (Test-Path $Config.SrvInfoPath)) {
        $CacheDirs = Get-ChildItem -Path $Config.SrvInfoPath -Directory -Filter "snccntx*" -ErrorAction SilentlyContinue
        Write-Host "  Директорий кэша: $($CacheDirs.Count)" -ForegroundColor $(if ($CacheDirs.Count -gt 0) { "Yellow" } else { "Gray" })
        
        if ($Config.ClusterNodes.Count -gt 0) {
            Write-Host "  Режим: Кластер ($($Config.ClusterNodes.Count) узлов)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "БЕЗОПАСНОСТЬ:" -ForegroundColor Green
    $Safe = Test-Safety
    Write-Host "  Активные сессии: $(if ($Safe) { 'НЕТ ✅' } else { 'ДА ⚠️' })" -ForegroundColor $(if ($Safe) { "Green" } else { "Red" })
    
    Write-Host ""
    Write-Host "РЕКОМЕНДУЕМАЯ КОМАНДА:" -ForegroundColor Cyan
    $Cmd = ".\Clear-1CServerCache.ps1"
    if ($Config.SrvInfoPath) { $Cmd += " -SrvInfoPath `"$($Config.SrvInfoPath)`"" }
    if ($Language -eq "ru-RU") { $Cmd += " -Language ru-RU" }
    Write-Host "  $Cmd" -ForegroundColor Yellow
}

# ============================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================

function Main {
    # Диагностический режим
    if ($Diagnostic) {
        Show-Diagnostics
        return
    }
    
    # Инициализация
    $LogFile = Initialize-Logging
    $Config = Get-1CFullConfiguration
    
    # Определение пути к кэшу
    $TargetPath = if ($SrvInfoPath) { 
        $SrvInfoPath 
    } elseif ($Config.SrvInfoPath) { 
        $Config.SrvInfoPath 
    } else {
        Write-Log -Message "Путь srvinfo не найден! Укажите вручную: -SrvInfoPath 'путь'" -Level "ERROR" -LogFile $LogFile
        throw "SrvInfo path not found"
    }
    
    # Проверка пути
    if (-not (Test-Path $TargetPath)) {
        Write-Log -Message "Путь не существует: $TargetPath" -Level "ERROR" -LogFile $LogFile
        throw "Path does not exist"
    }
    
    # Заголовок
    Write-Host "=== ОЧИСТКА КЭША 1С СЕРВЕРА ===" -ForegroundColor Cyan
    Write-Host "Версия: 3.0.0 | Язык: $Language" -ForegroundColor Gray
    Write-Host "Путь: $TargetPath" -ForegroundColor Green
    Write-Host "Режим: $(if ($WhatIf) { 'WhatIf (пробный)' } else { 'Выполнение' })" -ForegroundColor $(if ($WhatIf) { "Yellow" } else { "Green" })
    Write-Host ""
    
    if ($WhatIf) {
        Write-Host "!!! WHATIF MODE - ИЗМЕНЕНИЯ НЕ БУДУТ ВНЕСЕНЫ !!!" -ForegroundColor Red -BackgroundColor Black
        Write-Host ""
    }
    
    Write-Log -Message "Запуск очистки кэша 1С" -Level "INFO" -LogFile $LogFile
    
    # Проверки безопасности
    if (-not $Force) {
        if (-not (Test-Safety)) {
            Write-Log -Message "Проверки безопасности не пройдены! Используйте -Force для принудительной очистки" -Level "ERROR" -LogFile $LogFile
            throw "Safety checks failed"
        }
        Write-Log -Message "Проверки безопасности пройдены" -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Принудительный режим: проверки безопасности отключены" -Level "WARNING" -LogFile $LogFile
    }
    
    # Определение служб для остановки
    $ServicesToManage = @()
    if (-not $NoServiceRestart) {
        $ServicesToManage = @("1C:Enterprise 8.3 Server Agent", "1C:Enterprise 8.3 Server")
    }
    
    # Остановка служб
    $StoppedServices = @()
    if ($ServicesToManage.Count -gt 0) {
        Write-Log -Message "Останавливаем службы 1С..." -Level "INFO" -LogFile $LogFile
        $StoppedServices = Stop-1CServices -ServiceNames $ServicesToManage -Timeout $ServiceStopTimeout -LogFile $LogFile -WhatIf:$WhatIf
    }
    
    # Очистка кэша
    try {
        Clear-1CCache -SrvInfoPath $TargetPath -LogFile $LogFile -WhatIf:$WhatIf
    } catch {
        Write-Log -Message "Ошибка при очистке кэша: $($_.Exception.Message)" -Level "ERROR" -LogFile $LogFile
        throw
    }
    
    # Запуск служб
    if ($StoppedServices.Count -gt 0 -and -not $NoServiceRestart) {
        Write-Log -Message "Запускаем службы 1С..." -Level "INFO" -LogFile $LogFile
        Start-1CServices -ServiceNames $StoppedServices -LogFile $LogFile -WhatIf:$WhatIf
    }
    
    # Завершение
    Write-Log -Message "Очистка кэша успешно завершена" -Level "SUCCESS" -LogFile $LogFile
    Write-Host ""
    Write-Host "✅ ОЧИСТКА ЗАВЕРШЕНА УСПЕШНО" -ForegroundColor Green
    Write-Host "Лог сохранен: $LogFile" -ForegroundColor Gray
    
    if ($WhatIf) {
        Write-Host ""
        Write-Host "⚠️  Это был пробный запуск (WhatIf)" -ForegroundColor Yellow
        Write-Host "   Для реальной очистки запустите без параметра -WhatIf" -ForegroundColor Yellow
    }
}

# ============================================
# ЗАПУСК СКРИПТА
# ============================================

try {
    Main
} catch {
    Write-Host ""
    Write-Host "❌ ОШИБКА: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Подсказка: Используйте -Diagnostic для диагностики или -WhatIf для пробного запуска" -ForegroundColor Yellow
    exit 1
}
