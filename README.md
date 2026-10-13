# NetGuard — легковесный сканер уязвимостей для локальной сети

Инструмент для системных администраторов и инженеров ИБ. **Кроссплатформенный**
(Linux / macOS / Windows), работает **без root/администратора** и без сторонних
зависимостей (только стандартная библиотека Python ≥ 3.9).

## Возможности

- **Обнаружение хостов**: ping-сканирование подсети, чтение ARP-таблицы ОС,
  обратный DNS.
- **Сканирование портов**: TCP connect-скан с параллелизацией, таймаутами,
  диапазоном `top`-портов или произвольным CIDR-диапазоном.
- **Фингерпринт сервисов**: баннеры, HTTP(S)-запросы, TLS (версия протокола,
  сертификат, срок действия, самоподписанный, SHA1, слабые шифры).
- **Поиск известных уязвимостей по паттернам** (`plugins/vulns.py`):
  открытые «опасные» сервисы (Telnet, FTP анонимно, SMBv1, RDP NLA-off,
  VNC без пароля, X11, Docker API, Kubernetes, Elasticsearch/Memcached/Redis
  без авторизации, SNMP community `public`, MySQL без SSL, незащищённый LDAP,
  доступные панели управления и т.д.).
- **Отчёты**: JSON, CSV, HTML (готовый дашборд) — с CVSS-подобной оценкой риска.
- **Параллельное выполнение** через потоки (IO-bound), корректная работа Ctrl+C.

## Установка

```bash
# из исходников (рекомендуется виртуальное окружение)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install .
```

Или без установки (из каталога, где лежит папка `netguard`):

```bash
python -m netguard --help
```

Также поддерживается прямой запуск без установки — с любой ОС и из любого
каталога (Python 3.7+):

```bash
python netguard/__main__.py --help        # из корня проекта
python __main__.py --help                 # из папки netguard
py -m netguard --help                     # Windows Launcher вместо python
```

## Быстрый старт

```bash
# 1) Найти живые хосты в подсети
netguard discover 192.168.0.0/24

# 2) Отсканировать топ-100 портов на нескольких хостах
netguard scan 192.168.0.10 192.168.0.20 --top 100

# 3) Полное обследование: обнаружение + скан + плагины + HTML-отчёт
netguard audit 192.168.0.0/24 --top 100 -f html -o report.html

# Только конкретные порты
netguard scan gateway.local --ports 22,80,443,3389

# С экспортом во все форматы сразу
netguard audit 10.0.0.0/24 -f json,csv,html -o out_dir/
```

Все команды поддерживают `--threads`, `--timeout`, `-v/-vv`.

## Архитектура

```
netguard/
├── cli.py            # аргументы, подкоманды discover/scan/audit/plugins
├── config.py         # параметры запуска, нормализация целей (CIDR/IP/имя)
├── scan/
│   ├── discovery.py  # ICMP-ish ping (TCP-echo fallback), ARP, PTR
│   ├── portscan.py   # параллельный TCP connect-скан
│   └── fingerprint.py# баннеры, HTTP, TLS, идентификация сервиса
├── plugins/
│   ├── base.py       # интерфейс плагина + реестр
│   └── vulns.py      # проверки уязвимостей
├── models.py         # Host, Service, Finding, Risk
└── report/           # json_report, csv_report, html_report
```

Каждая проверка — это плагин с декларативными атрибутами (`id`, `title`,
`severity`, `cwe`, `references`, `remediation`). Новый плагин добавляется
декоратором `@register` в `plugins/vulns.py` — остальное делает ядро.

## Модель риска

| Severity | Вес | Пример |
|----------|-----|--------|
| critical | 10  | Docker API без авторизации, Redis/Elasticsearch без доступа к данным |
| high     | 7   | Telnet, анонимный FTP, SMBv1, VNC None-auth |
| medium   | 4   | истёкший сертификат, слабый TLS, SNMP public |
| low/info | 1/0 | самозаверенный cert, banner disclosure |

## Юридическая оговорка

Используйте инструмент **только на сетях и узлах, на которые у вас есть
письменное разрешение владельца**. Несанкционированное сканирование чужих
сетей может нарушать законодательство (например, ст. 272 УК РФ, CFAA в США).

## Возможная ошибка `ModuleNotFoundError: No module named 'netguard'`

Возникает, если запускать `python -m netguard`, находясь **внутри** папки
пакета `netguard/` (Python не может найти пакет из его же собственной папки).
Решения (любое):

```powershell
# 1) Проще всего — установите пакет один раз (рекомендуется):
py -m pip install .
netguard --version          # или py -m netguard из любой папки

# 2) Или запускайте из КОРНЯ проекта (где лежит pyproject.toml):
cd D:\netguard\netguard
py -m netguard scan 192.168.0.0/24

# 3) Или напрямую файлом — работает из любой директории:
py netguard\__main__.py --version

# 4) Или пропишите путь к проекту в PYTHONPATH venv (однократно):
py setup_hooks.py            # патчит activate/Activate.ps1 вашего .venv
.\.venv\Scripts\Activate.ps1 # пересоберите окружение после этого
cd netguard                  # теперь и отсюда python -m netguard работает
```

Скрипт `setup_hooks.py` безопасен для повторного запуска и поддерживает
PowerShell (`Activate.ps1`), cmd (`activate.bat`) и POSIX-шелли.
