# Zabbix Template: Proxmox Mail Gateway

Данный репозиторий содержит Zabbix-шаблон для пассивного мониторинга Proxmox Mail Gateway (PMG) версии 8.1 и выше. Шаблон собирает метрики по очереди писем, статусу службы Postfix, ресурсам (CPU, память, диск), а также содержит преднастроенные триггеры и графы.

## Содержание

    Возможности
    Структура репозитория
    Как использовать данный шаблон
    Требования
    Настройка PMG
    Как помочь проекту
    Лицензия
    Контакты

## Возможности

   ### Мониторинг очереди Postfix
        Метрика mail.queuesize: количество писем в очереди.
        Триггер, срабатывающий при превышении порога (задаётся макросом {$QUEUE_CRIT_LENGTH}).

   ### Статус службы Postfix
        Проверка postfix.status: выводит 1, если служба активна, и 0 при неактивном состоянии.
        Триггер «Postfix service is down» (при =0).

   ### Нагрузка CPU
        Метрика pmg.cpu.usage (в %).
        Триггер «High CPU usage on PMG» с порогом >90%.

   ### Использование оперативной памяти
        Метрика pmg.mem.usage (в %).
        Триггер «High memory usage on PMG» с порогом >80%.

   ### Использование диска
        Метрика pmg.disk.usage (в %).
        Триггер «Disk usage critical on PMG» с порогом >90%.

   ### Графики
        Граф «Postfix Queue length» (по очереди писем).
        Граф «PMG Resource Usage» (CPU, память и диск).

## Структура репозитория

````
zabbix-templates/
├─ Proxmox_MG_Passive/
│   └─ zbx_template.yml    # Последняя версия YAML-шаблона
│   └─ README.md           # Документация
└─ ...
````
    Proxmox_MG_Passive — папка, в которой хранится сам шаблон zbx_template.yml.
    README.md — данный файл с инструкциями.

## Как использовать данный шаблон

### Шаг 1. Склонировать репозиторий

git clone https://github.com/<ваш_логин>/zabbix-templates.git
cd zabbix-templates/Proxmox_MG_Passive

### Шаг 2. Импортировать шаблон в Zabbix

    Зайдите в веб-интерфейс Zabbix под учётной записью с правами супер-админа или администратора, у которого есть право на импорт шаблонов.
    Перейдите в раздел:
    Configuration → Templates → Import (или в зависимости от версии Zabbix — «Импорт шаблона»).
    Нажмите Выбрать файл (Choose File) и укажите путь к zbx_template.yml.
    При желании скорректируйте настройки импорта (перезапись существующих сущностей и т.п.).
    Нажмите Import.

### Шаг 3. Привязать шаблон к хосту PMG

    Создайте (или откройте существующий) Host для вашего Proxmox Mail Gateway.
    В разделе Templates, нажмите Add (или «Link new templates»), выберите «Proxmox MG Passive».
    Сохраните изменения.

    Примечание: Если у вас Zabbix Proxy, убедитесь, что Agent на PMG корректно направляет метрики на нужный Zabbix Proxy/Server, и что ключи (UserParameters) прописаны в /etc/zabbix/zabbix_agentd.conf.

## Требования

    Zabbix версии 7.0 или выше (шаблон тестировался на 7.2).
    Агент Zabbix установлен на PMG с нужными UserParameter (см. Настройка PMG).
    Право на импорт шаблонов в Zabbix (роль администратора).

## Настройка PMG

Для корректной работы шаблона необходимо добавить следующие UserParameter в конфигурацию агента Zabbix на вашем PMG-сервере (/etc/zabbix/zabbix_agentd.conf или файл include):

````
UserParameter=mail.queuesize,/usr/sbin/postqueue -p | tail -n 1 | awk '{ if ($5 == "") print "0"; else print $5; }'
UserParameter=postfix.status,systemctl is-active postfix | grep -q "active" && echo 1 || echo 0
UserParameter=pmg.cpu.usage,top -b -n 1 | grep "Cpu(s)" | awk '{print $2 + $4}'
UserParameter=pmg.mem.usage,free | grep Mem | awk '{print $3/$2 * 100.0}'
UserParameter=pmg.disk.usage,df / | tail -1 | awk '{print $5}' | sed 's/%//'
````

После внесения изменений перезапустите Zabbix Agent:

````
systemctl restart zabbix-agent
````

## Как помочь проекту

    Сообщить об ошибках и предложениях: Issues.
    Сделать Pull Request с исправлениями или улучшениями:
        Форкнуть репозиторий.
        Создать ветку feature/....
        Внести изменения в шаблон или документацию.
        Создать Pull Request в основную ветку.

## Лицензия

    Данный шаблон распространяется по лицензии GPLv3.

## Контакты

    Автор: Sergey Bezpalov
    Email: sergey@bezpalov.com

Спасибо за использование данного шаблона! Если возникнут вопросы — создавайте Issue в репозитории.
