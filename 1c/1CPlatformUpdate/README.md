# Documentation for Platform Installation Script

## Overview
This PowerShell script automates the installation and configuration of the 1C platform based on settings specified in a configuration file (`PlatformInstall.ini`). The script performs the following tasks:

1. Validates the configuration file and environment.
2. Checks the currently installed version of the 1C platform.
3. Installs or skips installation based on the version.
4. Copies necessary configuration files (`hasp.ini`).
5. Registers the `comcntr.dll` component.

## Prerequisites
- Windows operating system.
- PowerShell v5.1 or later.
- Administrator privileges.

## Installation Steps
1. Ensure the configuration file (`PlatformInstall.ini`) is accessible.
2. Save the script and configuration file to a secure directory.
3. Run the script with administrative privileges:
   ```powershell
   .\PlatformInstall.ps1
   ```

## Configuration File (`PlatformInstall.ini`)
The script uses a configuration file to define installation parameters. Below is an example configuration:

```ini
[INSTALL]
DistrDir=\\Server\Scripts\bin\
ProductCode={B26B9BD7-DA36-6A6B-9729-A559619283F6}
ProductVersion=8.3.25.1445
UpgradeCode={76AA2121-1E8C-4993-B980-49916CA2387C}
MsiPackage=1CEnterprise 8 (x86-64).msi
MsiOptions=THICKCLIENT=1 THINCLIENT=1 WEBSERVER=0 SERVER=0 CONFREPOSSERVER=0 CONVERTER77=0 SERVERCLIENT=1 LANGUAGES=RU
HaspIni=\\Server\Scripts\nethasp.ini
```

### Required Fields
- `DistrDir`: Directory containing installation files.
- `ProductCode`: GUID of the product.
- `ProductVersion`: Version of the platform to install.
- `MsiPackage`: Name of the MSI package.
- `MsiOptions`: Options passed to the MSI installer.
- `HaspIni`: Path to the `hasp.ini` file.

## Script Features

### Logging
The script logs messages with the following levels:
- **INFO**: General progress and steps.
- **ERROR**: Issues that cause script termination.

### Functions
#### Log-Event
Logs messages with a specified level.

#### Catch-Error
Handles and logs errors, then terminates the script.

#### Get-IniContent
Parses the configuration file and returns its content as a dictionary.

#### Get-InstalledVersion
Retrieves the currently installed version of the 1C platform from the Windows registry.

#### Copy-HaspIni
Copies the `hasp.ini` file to the appropriate directory (`C:\Program Files\1cv8\conf` or equivalent).

#### Register-ComCntrDll
Registers the `comcntr.dll` file from the `bin` directory of the installed platform.

## Execution Flow
1. The script reads and validates the configuration file.
2. It checks the installed version of the platform:
   - If the installed version is newer or equal to the target version, the script skips the installation.
   - Otherwise, it proceeds with installation.
3. The script installs the MSI package using options specified in the configuration file.
4. It copies the `hasp.ini` file to the required location.
5. The script registers the `comcntr.dll` component.

## Examples
Run the script to install or update the platform:
```powershell
.\PlatformInstall.ps1
```

## Troubleshooting
- **Configuration file not found**: Ensure the path to `PlatformInstall.ini` is correct.
- **HASP.INI not found**: Verify the file exists at the specified path.
- **DLL registration failed**: Ensure the `comcntr.dll` file exists in the `bin` directory.

## License
This script is distributed under the GPLv3 License.

## Contacts

    Author: Sergey Bezpalov
    Email: sergey@bezpalov.com

Thank you for using this template! If you have any questions, create an Issue in the repository.
