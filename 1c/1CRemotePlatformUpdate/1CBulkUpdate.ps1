# Список серверов для установки
$Servers = Get-Content ".\servers.lst"
$Version = "8.3.20.1612"

# Источник дистрибутивов
$SourcePath_x86 = "\\Server\Scripts\bin\$Version-86\"
$SourcePath_x64 = "\\Server\Scripts\bin\$Version-64\"
$Source1cestart_x86 = "\\Server\Scripts\bin\1cestart\x86\1cestart.cfg"
$Source1cestart_x64 = "\\Server\Scripts\bin\1cestart\x64\1cestart.cfg"

# Создаем лог файл
$LogFile = ".\install_log_$((Get-Date).ToString('yyyy-MM-dd_hh-mm')).txt"
Start-Transcript -Path $LogFile

# Функция для создания директории
function Create-Directory {
    param (
        [string]$Path
    )
    if(Test-Path $Path) {
        Remove-Item $Path\* -Recurse -Force
        Write-Host "$Path очищена" -ForegroundColor Green
    } else {
        New-Item -Path $Path -ItemType Directory
        Write-Host "$Path создана" -ForegroundColor Green
    }
}

# Функция для копирования файлов
function Copy-Files {
    param (
        [string]$Source,
        [string]$Destination
    )
    try {
        Copy-Item -Path $Source -Destination $Destination -Recurse -Force
        Write-Host "Файлы из $Source скопированы в $Destination" -ForegroundColor Green
    } catch {
        Write-Host "Файлы из $Source не скопированы в $Destination" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Функция для установки 1С
function Install-1C {
    param (
        [string]$Server,
        [string]$InstallPath,
        [string]$BinPath,
        [string]$VersionType
    )
    $Executable = "$BinPath\1cv8c.exe"
    if(!(Test-Path -Path $Executable)) {
        try {
            Invoke-Command -ComputerName $Server -ScriptBlock {
                param ($Path)
                Start-Process -FilePath $Path -Args '/s' -Wait
            } -ArgumentList $InstallPath
            Write-Host "$Server - Client 1C $VersionType установлен" -ForegroundColor Green
        } catch {
            Write-Host "$Server - Client 1C $VersionType не установлен" -ForegroundColor Red
        }
    } else {
        Write-Host "$Server - Client 1C $VersionType уже установлен" -ForegroundColor Yellow
    }
}

# Основной процесс установки
$Servers | ForEach-Object {
    $DestPath = "\\$_\C$\Temp_Install\"
    $InstallPath_x86 = "$DestPath\$Version-86\setup.exe"
    $InstallPath_x64 = "$DestPath\$Version-64\setup.exe"
    $DestPath1cestart = "\\$_\C$\ProgramData\1C\1CEStart\"
    $BinPath_x86 = "\\$_\C$\Program Files (x86)\1cv8\$Version\bin\"
    $BinPath_x64 = "\\$_\C$\Program Files\1cv8\$Version\bin\"
    
    # Создание директории Temp_Install
    Create-Directory -Path $DestPath

    # Копирование дистрибутивов
    Copy-Files -Source $SourcePath_x86 -Destination $DestPath
    Copy-Files -Source $SourcePath_x64 -Destination $DestPath

    # Копирование конфигурации 1CEStart
    Copy-Files -Source $Source1cestart_x86 -Destination $DestPath1cestart
    Copy-Files -Source $Source1cestart_x64 -Destination $DestPath1cestart

    # Установка 1С x86
    Install-1C -Server $_ -InstallPath $InstallPath_x86 -BinPath $BinPath_x86 -VersionType "x86"

    # Установка 1С x64
    Install-1C -Server $_ -InstallPath $InstallPath_x64 -BinPath $BinPath_x64 -VersionType "x64"

    # Удаление временной директории
    try {
        Remove-Item -Path $DestPath -Recurse -Force
        Write-Host "$DestPath удалена" -ForegroundColor Green
    } catch {
        Write-Host "$DestPath не удалена" -ForegroundColor Red
    }
}

# Остановка записи лога
Stop-Transcript
