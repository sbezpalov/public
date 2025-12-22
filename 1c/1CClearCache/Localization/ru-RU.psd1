@{
    Messages = @{
        ScriptStarted                  = "=== Очистка кэша 1C Сервера запущена (Версия: {0}) ==="
        AdminRequired                  = "Скрипт должен быть запущен от имени администратора."

        SafetyCheckPassed              = "Проверка безопасности пройдена: активные процессы 1С не найдены."
        SafetyCheckFailed              = "Проверка безопасности не пройдена: обнаружены активные процессы или сессии 1С."
        ForceSkipsSafety               = "Установлен параметр Force: проверки безопасности пропущены."
        ActiveSessionCheckDisabled     = "Проверка активных сессий отключена в settings.json."
        SafetyCheckPassed              = "Проверка безопасности пройдена."
        SafetyCheckFailed              = "Проверка безопасности не пройдена: активные процессы 1С обнаружены."
        
        ServiceNotFound                = "Служба не найдена: {0}"
        ServiceAlreadyStopped          = "Служба уже остановлена: {0}"
        ServiceStopping                = "Остановка службы: {0}"
        ServiceStopped                 = "Служба остановлена: {0}"
        ServiceStartFailed             = "Не удалось запустить службу {0}: {1}"
        ServiceStarting                = "Запуск службы: {0}"
        ServiceStarted                 = "Служба запущена: {0}"
        
        CacheCleanupStarting           = "Начинаем очистку кэша: {0}"
        PathNotFound                   = "Путь не найден: {0}"
        CacheDirsNotFound              = "Не найдено кэшированных директорий по пути {0}"
        CacheDirCleaned                = "Очищено: {0} ({1} файлов)"
        CacheDirFoundWhatIf            = "[WhatIf] Найдена кэшированная директория: {0} ({1} файлов)"
        CacheDirCleanError             = "Ошибка очистки {0}: {1}"
        CacheCleanupCompleted          = "Очистка кэша завершена: {0} директорий, {1} файлов"
        
        TempCleanupSkipped             = "Пропуск очистки временных файлов для системной учетной записи службы: {0}"
        TempPathNotFound               = "Путь для временных файлов не найден: {0}"
        TempCleanupFailed              = "Не удалось очистить временные файлы для {0}: {1}"
        TempCleanupCompleted           = "Очистка временных файлов завершена: {0} элементов удалено из {1} (учетная запись: {2})"
        DryRunNotice1                  = "Это был пробный запуск (WhatIf режим)."
        LogFilePath                    = "Файл лога: {0}"
        
        ForceParameterSkipped          = "Установлен параметр Force: пропуск проверки безопасности."
        AgentNotFoundInRegistry        = "Службы 1C ragent не найдены в реестре. Нечего очищать."
        SrvInfoNotDetermined           = "Не удалось определить SrvInfoPath из реестра. Укажите -SrvInfoPath."
        ServicesStopping               = "Остановка служб 1С..."
        ServicesStarting               = "Запуск служб 1С..."
        Completion                     = "Очистка кэша завершена успешно."
    }
}
