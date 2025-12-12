@{
    Messages = @{
        ScriptStarted                  = "=== Очистка кэша 1C Сервера запущена (Версия: {0}) ==="
        AdminRequired                  = "Скрипт должен быть запущен от имени администратора."

        SafetyCheckPassed              = "Проверка безопасности пройдена: активные процессы 1С не найдены."
        SafetyCheckFailed              = "Проверка безопасности не пройдена: обнаружены активные процессы или сессии 1С."
        ForceSkipsSafety               = "Установлен параметр Force: проверки безопасности пропущены."
        ActiveSessionCheckDisabled     = "Проверка активных сессий 1С отключена в settings.json."

        SrvInfoNotDetermined           = "Не удалось определить SrvInfoPath. Укажите -SrvInfoPath или настройте его в settings.json."
        SrvInfoPathUnusual             = "SrvInfoPath выглядит нетипично: {0}"
        SrvInfoPathUnusualNeedForce    = "Используйте -Force для работы с нестандартным SrvInfoPath."
        PathNotFound                   = "Путь не найден: {0}"

        ServicesStopping               = "Останавливаем службы 1С..."
        ServicesStarting               = "Запускаем службы 1С..."
        ServiceNotFound                = "Служба не найдена: {0}"
        ServiceAlreadyStopped          = "Служба уже остановлена: {0}"
        ServiceStopping                = "Останавливаем службу: {0}"
        ServiceStopped                 = "Служба остановлена: {0}"
        ServiceStarting                = "Запускаем службу: {0}"
        ServiceStarted                 = "Служба запущена: {0} (Статус: {1})"
        ServiceStopFailed              = "Ошибка остановки службы {0}: {1}"
        ServiceStartFailed             = "Ошибка запуска службы {0}: {1}"

        CleanupStarting                = "Начинаем очистку кэша: {0}"
        CacheDirsNotFound              = "Директории кэша не найдены в {0}"
        CacheDirFoundWhatIf            = "[WhatIf] Найдена директория кэша: {0} ({1} файлов)"
        CacheDirCleaned                = "Очищено: {0} ({1} файлов)"
        CacheDirCleanError             = "Ошибка очистки {0}: {1}"
        CacheCleanupCompleted          = "Очистка кэша завершена: {0} директорий, {1} файлов"

        Completion                     = "Очистка кэша успешно завершена."
        LogFilePath                    = "Лог-файл: {0}"
        DryRunNotice1                  = "Это был пробный запуск (WhatIf)."
        DryRunNotice2                  = "Запустите без -WhatIf для реальной очистки."

        HintDiagnosticWhatIf           = "Подсказка: используйте -Diagnostic для диагностики или -WhatIf для пробного запуска."
    }

    ServiceNames = @{
        Agent  = "Агент сервера 1С:Предприятие 8.3"
        Server = "Сервер 1С:Предприятие 8.3"
    }

    Prompts = @{
        ConfirmCleanup        = "Продолжить очистку кэша? [Д/Н]: "
        WarningActiveSessions = "ВНИМАНИЕ: Найдены активные процессы 1С."
        WhatIfMode            = "РЕЖИМ WHATIF - Изменения не будут внесены."
    }

    Diagnostics = @{
        Header               = "=== ДИАГНОСТИКА 1С СЕРВЕРА ==="
        AgentServiceHeader   = "СЛУЖБА АГЕНТА:"
        AgentNotFound        = "Служба агента не найдена."
        ParametersHeader     = "Параметры:"
        ClustersHeader       = "КЛАСТЕРЫ:"
        ClusterNotFound      = "Информация о кластерах не найдена."
        SafetyHeader         = "БЕЗОПАСНОСТЬ:"
        RecommendedCmdHeader = "РЕКОМЕНДУЕМАЯ КОМАНДА:"
        NotDetected          = "<не определено>"
        ActiveNone           = "НЕТ активных процессов 1С"
        ActiveDetected       = "ОБНАРУЖЕНЫ активные процессы 1С"
    }
}
