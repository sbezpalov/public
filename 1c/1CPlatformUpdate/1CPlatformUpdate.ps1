# 1C Platform Update v.1.0, could be used with Group Policy
# ( with comcntr.dll registration and hasp.ini distribution )

# Path to the configuration file
$configFilePath = "\\Servers\Scripts\PlatformInstall.ini"

# Function to log events
function Log-Event {
    param (
        [string]$Level,
        [string]$Message
    )
    Write-Host "[$Level] $Message"
}

# Function to handle errors
function Catch-Error {
    param (
        [string]$ErrorMessage
    )
    if ($ErrorMessage) {
        Log-Event -Level "ERROR" -Message $ErrorMessage
        exit 1
    }
}

# Function to parse INI file
function Get-IniContent {
    param (
        [string]$FilePath
    )

    $iniContent = @{}
    $currentSection = ""

    foreach ($line in Get-Content -Path $FilePath) {
        if ($line -match "^\[(.+)\]") {
            $currentSection = $matches[1]
            $iniContent[$currentSection] = @{}
        } elseif ($line -match "^([^;].+?)=(.+)") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $iniContent[$currentSection][$key] = $value
        }
    }

    return $iniContent
}

# Function to get the installed version of 1C platform
function Get-InstalledVersion {
    $primaryRegistryPath = "HKLM:\SOFTWARE\1C\1Cv8"
    $alternateRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\1C\1Cv8"
    
    try {
        if (Test-Path -Path $primaryRegistryPath) {
            $installedVersion = (Get-ItemProperty -Path $primaryRegistryPath).Version
            return $installedVersion
        } elseif (Test-Path -Path $alternateRegistryPath) {
            $installedVersion = (Get-ItemProperty -Path $alternateRegistryPath).Version
            return $installedVersion
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

# Function to copy hasp.ini file
function Copy-HaspIni {
    param (
        [string]$HaspIniSource
    )

    if (-Not (Test-Path -Path $HaspIniSource)) {
        Log-Event -Level "INFO" -Message "HASP.INI file not found at $HaspIniSource. Skipping copy step."
        return
    }

    $is64Bit = ([System.Environment]::Is64BitOperatingSystem)
    $destinationPath = if ($is64Bit) {
        "C:\\Program Files\\1cv8\\conf"
    } else {
        "C:\\Program Files (x86)\\1cv8\\conf"
    }

    try {
        New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
        Copy-Item -Path $HaspIniSource -Destination $destinationPath -Force
        Log-Event -Level "INFO" -Message "Copied HASP.INI from $HaspIniSource to $destinationPath."
    } catch {
        Catch-Error -ErrorMessage "Failed to copy HASP.INI: $_.Exception.Message"
    }
}

# Function to register comcntr.dll
function Register-ComCntrDll {
    param (
        [string]$ProductVersion
    )

    $is64Bit = ([System.Environment]::Is64BitOperatingSystem)
    $basePath = if ($is64Bit) {
        "C:\\Program Files\\1cv8"
    } else {
        "C:\\Program Files (x86)\\1cv8"
    }
    $binDirectory = Join-Path -Path $basePath -ChildPath "$ProductVersion\\bin"
    $dllPath = Join-Path -Path $binDirectory -ChildPath "comcntr.dll"

    if (-Not (Test-Path -Path $dllPath)) {
        Log-Event -Level "ERROR" -Message "comcntr.dll not found at $dllPath. Registration failed."
        return
    }

    try {
        $regsvr32Cmd = "regsvr32 /s `"$dllPath`""
        Log-Event -Level "INFO" -Message "Registering comcntr.dll using command: $regsvr32Cmd"
        Invoke-Expression -Command $regsvr32Cmd
        Log-Event -Level "INFO" -Message "comcntr.dll registered successfully."
    } catch {
        Catch-Error -ErrorMessage "Failed to register comcntr.dll: $_.Exception.Message"
    }
}

# Read configuration file
if (-Not (Test-Path -Path $configFilePath)) {
    Catch-Error -ErrorMessage "Configuration file not found at $configFilePath."
}

$config = Get-IniContent -FilePath $configFilePath
$installConfig = $config['INSTALL']

# Validate required configuration fields
$requiredFields = @("DistrDir", "ProductCode", "ProductVersion", "MsiPackage", "MsiOptions", "HaspIni")
foreach ($field in $requiredFields) {
    if (-Not $installConfig.ContainsKey($field)) {
        Catch-Error -ErrorMessage "Missing required field `$field in configuration file."
    }
}

# Check installed version
$installedVersion = Get-InstalledVersion
$targetVersion = $installConfig['ProductVersion']

if ($installedVersion -and ([version]$installedVersion -ge [version]$targetVersion)) {
    Log-Event -Level "INFO" -Message "Installed version ($installedVersion) is up-to-date or newer than target version ($targetVersion). Skipping installation."
    exit 0
}

# Installation logic
$msiPath = Join-Path -Path $installConfig['DistrDir'] -ChildPath $installConfig['MsiPackage']
$msiOptions = $installConfig['MsiOptions']

if (-Not (Test-Path -Path $msiPath)) {
    Catch-Error -ErrorMessage "MSI package not found at $msiPath."
}

# Execute MSI installation
$arguments = "/i `"$msiPath`" $msiOptions /quiet /norestart"
Log-Event -Level "INFO" -Message "Starting installation of $msiPath with options: $msiOptions"

try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow
    Log-Event -Level "INFO" -Message "Installation completed successfully."
} catch {
    Catch-Error -ErrorMessage $_.Exception.Message
}

# Copy HASP.INI file after installation
$haspIniSource = $installConfig['HaspIni']
Copy-HaspIni -HaspIniSource $haspIniSource

# Register comcntr.dll after installation
$productVersion = $installConfig['ProductVersion']
Register-ComCntrDll -ProductVersion $productVersion
