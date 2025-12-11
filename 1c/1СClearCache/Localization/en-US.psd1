@{
    Messages = @{
        ScriptStarted                  = "=== 1C Server Cache Cleaner started (Version: {0}) ==="
        AdminRequired                  = "Script must be run as Administrator."

        SafetyCheckPassed              = "Safety check passed: no active 1C processes found."
        SafetyCheckFailed              = "Safety check failed: active 1C processes or sessions detected."
        ForceSkipsSafety               = "Force parameter is set: safety checks are skipped."
        ActiveSessionCheckDisabled     = "Active 1C session check is disabled in settings.json."

        SrvInfoNotDetermined           = "SrvInfoPath could not be determined. Specify -SrvInfoPath or configure it in settings.json."
        SrvInfoPathUnusual             = "SrvInfoPath looks unusual: {0}"
        SrvInfoPathUnusualNeedForce    = "Use -Force to work with a non-standard SrvInfoPath."
        PathNotFound                   = "Path not found: {0}"

        ServicesStopping               = "Stopping 1C services..."
        ServicesStarting               = "Starting 1C services..."
        ServiceNotFound                = "Service not found: {0}"
        ServiceAlreadyStopped          = "Service already stopped: {0}"
        ServiceStopping                = "Stopping service: {0}"
        ServiceStopped                 = "Service stopped: {0}"
        ServiceStarting                = "Starting service: {0}"
        ServiceStarted                 = "Service started: {0} (Status: {1})"
        ServiceStopFailed              = "Failed to stop service {0}: {1}"
        ServiceStartFailed             = "Failed to start service {0}: {1}"

        CleanupStarting                = "Starting cache cleanup: {0}"
        CacheDirsNotFound              = "No cache directories found under {0}"
        CacheDirFoundWhatIf            = "[WhatIf] Found cache directory: {0} ({1} files)"
        CacheDirCleaned                = "Cleaned: {0} ({1} files)"
        CacheDirCleanError             = "Error cleaning {0}: {1}"
        CacheCleanupCompleted          = "Cache cleanup completed: {0} directories, {1} files"

        Completion                     = "Cache cleanup completed successfully."
        LogFilePath                    = "Log file: {0}"
        DryRunNotice1                  = "This was a dry run (WhatIf mode)."
        DryRunNotice2                  = "Run without -WhatIf to perform actual cleanup."

        HintDiagnosticWhatIf           = "Hint: use -Diagnostic for diagnostics or -WhatIf for a dry run."
    }

    ServiceNames = @{
        Agent  = "1C:Enterprise 8.3 Server Agent"
        Server = "1C:Enterprise 8.3 Server"
    }

    Prompts = @{
        ConfirmCleanup        = "Proceed with cache cleanup? [Y/N]: "
        WarningActiveSessions = "WARNING: Active 1C processes found."
        WhatIfMode            = "WHATIF MODE - No changes will be made."
    }

    Diagnostics = @{
        Header               = "=== 1C SERVER DIAGNOSTICS ==="
        AgentServiceHeader   = "AGENT SERVICE:"
        AgentNotFound        = "Agent service not found."
        ParametersHeader     = "Parameters:"
        ClustersHeader       = "CLUSTERS:"
        ClusterNotFound      = "Cluster information not found."
        SafetyHeader         = "SAFETY:"
        RecommendedCmdHeader = "RECOMMENDED COMMAND:"
        NotDetected          = "<not detected>"
        ActiveNone           = "NO active 1C processes"
        ActiveDetected       = "ACTIVE 1C processes detected"
    }
}
