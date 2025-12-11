@{
    Messages = @{
        ScriptStarted = "=== Очистка кэша 1C Сервера запущена (Версия: {0}) ==="
        SafetyCheckPassed = "Проверка безопасности пройдена: активные сессии 1С не найдены"
        SafetyCheckFailed = "КРИТИЧЕСКИЙ СБОЙ: Обнаружены активные сессии 1С"
        ServiceStopped = "Служба остановлена: {0}"
        ServiceStarted = "Служба запущена: {0}"
        CacheCleaned = "Кэш очищен: {0} директорий, {1} файлов"
        Completion = "Очистка кэша успешно завершена"
    }
    
    ServiceNames = @{
        Agent = "Агент сервера 1С:Предприятие 8.3"
        Server = "Сервер 1С:Предприятие 8.3"
    }
    
    Prompts = @{
        ConfirmCleanup = "Продолжить очистку кэша? [Д/Н]: "
        WarningActiveSessions = "ВНИМАНИЕ: Найдены активные сессии 1С"
        WhatIfMode = "РЕЖИМ WHATIF - Изменения не будут внесены"
    }
}
