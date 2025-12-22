@{
    Messages = @{
        ScriptStarted                  = "=== 1C Server Cache Cleaner started (Version: {0}) ==="
        AdminRequired                  = "Script must be run as Administrator."

        SafetyCheckPassed              = "Safety check passed: no active 1C processes found."
        SafetyCheckFailed              = "Safety check failed: active 1C processes or sessions detected."
        ForceSkipsSafety               = "Force parameter is set: safety checks are skipped."
        ActiveSessionCheckDisabled     = "Active session check is disabled in settings.json."
        SafetyCheckPassed              = "Safety check passed."
        SafetyCheckFailed              = "Safety check failed: active 1C processes detected."
        
        ServiceNotFound                = "Service not found: {0}"
        ServiceAlreadyStopped          = "Service already stopped: {0}"
        ServiceStopping                = "Stopping service: {0}"
        ServiceStopped                 = "Service stopped: {0}"
        ServiceStartFailed             = "Failed to start service {0}: {1}"
        ServiceStarting                = "Starting service: {0}"
        ServiceStarted                 = "Service started: {0}"
        
        CacheCleanupStarting           = "Starting cache cleanup: {0}"
        PathNotFound                   = "Path not found: {0}"
        CacheDirsNotFound              = "No cache directories found under {0}"
        CacheDirCleaned                = "Cleaned: {0} ({1} files)"
        CacheDirFoundWhatIf            = "[WhatIf] Found cache directory: {0} ({1} files)"
        CacheDirCleanError             = "Error cleaning {0}: {1}"
        CacheCleanupCompleted          = "Cache cleanup completed: {0} directories, {1} files"
        
        TempCleanupSkipped             = "Temp cleanup skipped for system service account: {0}"
        TempPathNotFound               = "Temp path not found: {0}"
        TempCleanupFailed              = "Temp cleanup failed for {0}: {1}"
        TempCleanupCompleted           = "Temp cleanup completed: {0} items removed from {1} (account: {2})"
        DryRunNotice1                  = "This was a dry run (WhatIf mode)."
        LogFilePath                    = "Log file: {0}"
        
        ForceParameterSkipped          = "Force parameter is set: skipping safety checks."
        AgentNotFoundInRegistry        = "1C ragent services not found in registry. Nothing to do."
        SrvInfoNotDetermined           = "SrvInfoPath could not be determined from registry. Specify -SrvInfoPath."
        ServicesStopping               = "Stopping 1C services..."
        ServicesStarting               = "Starting 1C services..."
        Completion                     = "Cache cleanup completed successfully."
    }
}

