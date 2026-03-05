# Standalone Whitelist Checker

Реализация ТЗ: сбор, дедуп и проверка прокси-конфигов с Xray/Hysteria, egress whitelist, speedtest, статистика и cleanup.

## Быстрый старт

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
whitelist-checker --help
```

### Минимальный запуск

```bash
whitelist-checker --mode merge --links-file links.txt --output-dir configs
```

### Пример LINKS_FILE

```
# комментарий
https://example.com/list1.txt https://example.com/list2.txt
https://example.com/list3.txt
```

### Выходные файлы

- `white-list_available`
- `white-list_available(top100)`
- `white-list_available_st`
- `white-list_available_st(top100)`
- `white-list_available_source_stats.txt`

### Переменные окружения (дефолты в .env.example)

- MODE, LINKS_FILE, DEFAULT_LIST_URL
- OUTPUT_DIR, OUTPUT_FILE
- CIDR_WHITELIST_URL
- EGRESS_MODE (off|iptables|linux-netns)
- XRAY_PATH, HYSTERIA_PATH
- SPEED_TEST_ENABLED, SPEED_TEST_MODE, SPEED_TEST_METRIC, MIN_SPEED_THRESHOLD_MBPS
- STRONG_* и прочие таймауты (см. config.py)

### Smoke тест

```bash
whitelist-checker --mode merge --links-file links.txt --output-dir configs --egress-mode off --speedtest false
ls configs
```

## Тесты

```
pytest
```
