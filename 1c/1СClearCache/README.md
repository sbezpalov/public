# 🚀 1C Server Cache Cleaner Professional

A minimalistic, powerful PowerShell script for automated cleaning of 1C Enterprise Server session cache with intelligent registry detection and multi-language support.

## ✨ Features

### 🔍 Smart Detection
- **Automatic Registry Reading** - Finds 1C installation paths from Windows Registry
- **Multi-Version Support** - Works with 1C 8.2, 8.3, and newer versions
- **Cluster Aware** - Automatically detects 1C cluster configurations
- **Architecture Detection** - Supports x86, x64, and x86-64 installations

### 🛡️ Safety First
- **Active Session Detection** - Prevents cleaning during active 1C user sessions
- **Graceful Service Management** - Proper service stop/start sequences
- **Dry Run Mode** - Preview actions without execution (`-WhatIf`)
- **Force Mode** - Bypass safety checks when needed (`-Force`)

### 🌐 Multi-Language
- **Full Localization** - English (en-US) and Russian (ru-RU) support
- **Automatic Detection** - Uses system language by default
- **Easy to Extend** - Add new languages by creating `.psd1` files

### 📊 Production Ready
- **Comprehensive Logging** - Console, file, and Windows Event Log
- **Error Handling** - Proper error recovery and reporting
- **Parameterized** - Flexible command-line options
- **Scheduling Ready** - Easy integration with Task Scheduler

## 🚀 Quick Start

### Prerequisites
- **Windows Server** 2012 R2 or later
- **PowerShell** 5.1 or higher
- **1C Enterprise Server** 8.2 or later
- **Administrative privileges**
