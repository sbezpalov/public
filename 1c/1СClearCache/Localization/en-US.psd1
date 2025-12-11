@{
    Messages = @{
        ScriptStarted = "=== 1C Server Cache Cleaner started (Version: {0}) ==="
        SafetyCheckPassed = "Safety check passed: No active 1C sessions found"
        SafetyCheckFailed = "CRITICAL: Active 1C sessions detected"
        ServiceStopped = "Service stopped: {0}"
        ServiceStarted = "Service started: {0}"
        CacheCleaned = "Cache cleaned: {0} directories, {1} files"
        Completion = "Cache cleanup completed successfully"
    }
    
    ServiceNames = @{
        Agent = "1C:Enterprise 8.3 Server Agent"
        Server = "1C:Enterprise 8.3 Server"
    }
    
    Prompts = @{
        ConfirmCleanup = "Proceed with cache cleanup? [Y/N]: "
        WarningActiveSessions = "WARNING: Active 1C sessions found"
        WhatIfMode = "WHATIF MODE - No changes will be made"
    }
}
