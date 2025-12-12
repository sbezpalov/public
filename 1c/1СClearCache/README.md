# Clear-1CServerCache

Enterprise-grade PowerShell script for safe cleanup of **1C:Enterprise server cache** in maintenance windows.

The script is designed for production environments and follows a strict principle:

> **If 1C services are not registered in the Windows registry, there is nothing to clean.**

Registry is the single source of truth.

---

## Key Features

- Registry-driven detection of 1C server services (`ragent.exe`)
- Automatic discovery of `SrvInfoPath` from service startup parameters (`-d`)
- Safe maintenance workflow:
  - Stop services
  - Clean server cache
  - Start services
- Correct service restart order:
  - Stop: **Server → Agent**
  - Start: **Agent → Server**
- Native PowerShell `-WhatIf` / `-Confirm` support
- Robust localization support (EN / RU)
- ASCII-only script body (UTF only in localization files)
- Designed for scheduled maintenance windows

---

## Requirements

- Windows Server / Windows with 1C:Enterprise Server installed
- PowerShell 5.1+
- Administrative privileges

---

## Usage

```powershell
.\Clear-1CServerCache.ps1
```

Dry run:

```powershell
.\Clear-1CServerCache.ps1 -WhatIf
```

---

## Version

Current version: **3.1.5**
