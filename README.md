# Standalone Whitelist Checker

Инструмент на Python 3.11+ для сбора прокси‑конфигов из разных источников,
дедупликации, проверки доступности через реальные движки (Xray / Hysteria),
опционального speedtest и формирования пяти стандартизированных файлов
whitelist.

---

## Требования

- Python 3.11+
- Для режима `real` нужны бинарники `xray` и/или `hysteria` в `$PATH`.
  Если бинарник не найден, он будет **автоматически загружен** из официального
  GitHub-релиза и сохранён в `~/.cache/white_chek/bin` (см. раздел «Бинарники движков»).
- Для egress‑режимов `iptables` и `linux-netns` нужен root на Linux.
- Для egress-режима `docker` нужен работающий Docker (Windows или Linux).

---

## Установка

```bash
pip install -e .
cp .env.example .env
```

---

## Быстрый старт (пример работы)

```bash
# Запуск с явным отключением egress (требует флага подтверждения)
whitelist-checker \
  --links-file links.txt \
  --output-dir configs \
  --egress-mode off \
  --egress-allow-off \
  --no-speedtest

# Запуск в stub‑режиме (без реальных движков и без доступа в интернет)
whitelist-checker \
  --links-file links.txt \
  --output-dir configs \
  --engine-mode stub \
  --egress-mode off \
  --egress-allow-off \
  --no-speedtest
```

После успешного запуска появятся **ровно 5 файлов** в `configs/`:

```
configs/white-list_available
configs/white-list_available(top100)
configs/white-list_available_st
configs/white-list_available_st(top100)
configs/white-list_available_source_stats.txt
```

---

## Примеры работы

### Дымовой тест (реальные источники, egress off, speedtest off)

```bash
# Дымовой тест (реальные источники, egress off — явное подтверждение, speedtest off)
cat > /tmp/smoke_links.txt << 'EOF'
# Добавьте 1–2 реальных URL со списками прокси
https://raw.githubusercontent.com/example/list/main/proxies.txt
EOF

# 2. Запуск
whitelist-checker \
  --links-file /tmp/smoke_links.txt \
  --output-dir /tmp/smoke_out \
  --egress-mode off \
  --egress-allow-off \
  --no-speedtest

# 3. Проверить, что создано 5 файлов
ls /tmp/smoke_out/
# Ожидается:
#   white-list_available
#   white-list_available(top100)
#   white-list_available_st
#   white-list_available_st(top100)
#   white-list_available_source_stats.txt
```

### Интеграционные тесты (stub, офлайн, без бинарников)

```bash
# Запуск только stub‑интеграционного теста
python -m pytest tests/test_integration_stub.py -v

# Запуск только egress-тестов
python -m pytest tests/test_egress.py -v

# Запуск только download-тестов (всё замокано, без сети)
python -m pytest tests/test_download.py -v

# Запуск всех тестов
python -m pytest tests/ -v
```

Интеграционные тесты:
- мокают HTTP‑запросы к источникам (интернет не нужен)
- используют `ENGINE_MODE=stub` (Xray/Hysteria не требуются)
- проверяют, что создаются ровно 5 выходных файлов
- проверяют формат файла статистики источников и мульти‑credit подсчёт
- проверяют исключение и дополнение `notworkers`
- проверяют, что `_st` файлы создаются даже при выключенном speedtest

---

## Формат входных файлов

- `links.txt` (или файл из `--links-file`) — по одной ссылке на строку,
  комментарии начинаются с `#`. В строке может быть несколько URL,
  они будут разобраны по пробелам.
- `notworkers` (в `OUTPUT_DIR`) — список ключей, которые нужно исключить
  из проверки. При включённом `USE_NOTWORKERS=true` нерабочие ключи
  автоматически дописываются в этот файл.

---

## Выходные файлы

| Файл | Описание |
|---|---|
| `white-list_available` | Рабочие прокси, отсортированные по latency (возрастание) |
| `white-list_available(top100)` | Топ‑100 самых быстрых из `white-list_available` |
| `white-list_available_st` | Результат после speedtest (или копия `available`, если speedtest выключен) |
| `white-list_available_st(top100)` | Топ‑100 из speedtest‑результата |
| `white-list_available_source_stats.txt` | `# working_count TAB source_url`, сортировка по count ASC, затем URL ASC; один рабочий ключ засчитывается для каждого источника, где он встречался |

`KEEP_ONLY_WHITELIST_FILES=true` (по умолчанию) удаляет все лишние файлы из
`OUTPUT_DIR` после успешного запуска.

---

## Режимы egress

По умолчанию egress включён (`enforced`) — автоматически выбирается лучший backend.
Чтобы **явно** отключить egress, нужно передать `--egress-mode off --egress-allow-off`
(или `EGRESS_ALLOW_OFF=true`).

| Режим | Поведение |
|---|---|
| `enforced` | **(по умолчанию)** Автовыбор: `iptables` на Linux, `docker` на Windows. Завершается с ошибкой, если нужный backend недоступен. |
| `iptables` | Выставляет `OUTPUT=DROP`, разрешает lo, ESTABLISHED/RELATED, DNS на 8.8.8.8/8.8.4.4/1.1.1.1 и CIDR‑список. Правила откатываются при выходе. |
| `linux-netns` | Создаёт netns с veth, включает MASQUERADE и применяет те же правила. Полная очистка при выходе. |
| `docker` | Запускает Alpine-контейнер с `NET_ADMIN`, применяет iptables-правила внутри контейнера. Контейнер удаляется при выходе. Работает на Windows и Linux. |
| `off` | Без ограничений сети. **Требует** флага `--egress-allow-off` (или `EGRESS_ALLOW_OFF=true`). |

### EGRESS_BACKEND

Переменная `EGRESS_BACKEND` (или `--egress-backend`) позволяет явно выбрать backend:
- `native` — использовать iptables напрямую (по умолчанию на Linux)
- `docker` — использовать Docker/Podman (переопределяет автовыбор)

### Если CIDR-список недоступен

Если `CIDR_WHITELIST_URL` / `CIDR_WHITELIST_FILE` не загружается или пуст, программа
завершится с ошибкой и чётким сообщением. Пустой список не принимается.

> **Важно:** `iptables` и `linux-netns` требуют root‑доступа и всегда откатываются даже при аварийном завершении.

---

## Справка по CLI (флаги запуска)

Приоритет настроек: **CLI флаг → переменная окружения → значение по умолчанию**.
Полный список переменных окружения см. в разделе ниже.

### Основные флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--mode` | `merge` | Режим работы (`merge`/`single`, зарезервировано для будущей логики) |
| `--links-file` | `links.txt` | Файл со ссылками на источники |
| `--default-list-url` | — | Резервный URL (пока не используется в коде) |
| `--output-dir` | `configs` | Директория для результатов |
| `--output-file` | `white-list_available` | Базовое имя выходных файлов |
| `--egress-mode` | `enforced` | Ограничение сети: `enforced`, `off`, `iptables`, `linux-netns`, `docker` |
| `--egress-backend` | `native` | Backend для режима enforced/docker: `native` (iptables), `docker` |
| `--egress-allow-off` | выключен | Подтверждение для `--egress-mode off` (обязателен при отключении egress) |
| `--cidr-whitelist-url` | `https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt` | URL со списком CIDR для egress‑режимов |
| `--cidr-whitelist-file` | — | Локальный файл CIDR (имеет приоритет над URL) |
| `--engine-mode` | `real` | `real` (Xray/Hysteria) или `stub` (все ключи OK) |
| `--xray-path` | авто | Путь до бинарника `xray` |
| `--hysteria-path` | авто | Путь до бинарника `hysteria` |

### Булевы флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--speedtest` / `--no-speedtest` | включён | Запуск speedtest‑пайплайна |
| `--recheck-previous` / `--no-recheck-previous` | включён | Подмешивать предыдущий whitelist |
| `--use-notworkers` / `--no-use-notworkers` | включён | Исключать и дополнять `notworkers` |
| `--require-https` / `--no-require-https` | включён | Требовать HTTPS в проверках |
| `--verify-https-ssl` / `--no-verify-https-ssl` | выключен | Проверять SSL‑сертификаты HTTPS |
| `--strong-style-test` / `--no-strong-style-test` | включён | Включать строгую проверку HTTP |
| `--strong-double-check` / `--no-strong-double-check` | включён | Повторная проверка при строгом режиме |
| `--keep-only-whitelist-files` / `--no-keep-only-whitelist-files` | включён | Оставлять только whitelist‑файлы |

### Потоки и порты

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--threads` | `200` | Максимум параллельных воркеров |
| `--base-port` | `20000` | Первый SOCKS‑порт |

### Настройки HTTP‑проверок

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--strong-style-timeout` | `12` | Таймаут строгой проверки (сек) |
| `--strong-max-response-time` | `3` | Максимальное время ответа (сек) |
| `--strong-attempts` | `3` | Количество попыток строгой проверки |
| `--requests-per-url` | `2` | Кол-во запросов на URL |
| `--min-successful-requests` | `2` | Минимум успешных запросов |
| `--min-successful-urls` | `2` | Минимум успешных URL |
| `--request-delay` | `0.1` | Задержка между запросами (сек) |
| `--connect-timeout` | `6` | Таймаут соединения (сек) |
| `--connect-timeout-slow` | `15` | Таймаут для медленных соединений (сек) |
| `--max-response-time` | `6` | Максимальное время ответа (сек) |
| `--max-latency-ms` | `2000` | Максимальная задержка (мс) |
| `--max-retries` | `1` | Количество ретраев |
| `--retry-delay-base` | `0.5` | Базовая задержка ретрая (сек) |
| `--retry-delay-multiplier` | `2.0` | Множитель задержки ретрая |
| `--stability-checks` | `2` | Проверок стабильности |
| `--stability-check-delay` | `2.0` | Задержка между проверками (сек) |
| `--test-urls` | `http://www.google.com/generate_204,http://www.cloudflare.com/cdn-cgi/trace` | Список HTTP URL через запятую |
| `--test-urls-https` | `https://www.gstatic.com/generate_204` | Список HTTPS URL через запятую |

### Запуск движка

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--xray-startup-wait` | `1.2` | Время ожидания старта Xray (сек) |
| `--xray-startup-poll-interval` | `0.2` | Интервал проверки запуска Xray (сек) |

### Speedtest

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--speed-test-timeout` | `2` | Таймаут speedtest (сек) |
| `--speed-test-mode` | `latency` | Режим speedtest |
| `--speed-test-metric` | `latency` | Метрика speedtest |
| `--speed-test-requests` | `5` | Кол-во запросов |
| `--speed-test-url` | `https://www.gstatic.com/generate_204` | URL для speedtest |
| `--speed-test-workers` | `200` | Воркеры speedtest |
| `--speed-test-download-timeout` | `30` | Таймаут загрузки (сек) |
| `--speed-test-download-url-small` | `https://speed.cloudflare.com/__down?bytes=250000` | Малый файл для загрузки |
| `--speed-test-download-url-medium` | `https://speed.cloudflare.com/__down?bytes=1000000` | Средний файл для загрузки |
| `--min-speed-threshold-mbps` | `2.5` | Минимальная скорость (Мбит/с) |
| `--speed-test-download-chunksize` | `32768` | Размер чанка загрузки |

---

## Справка по переменным окружения (.env)

Ниже перечислены переменные окружения из `.env.example`.

### Core

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MODE` | `merge` | Режим работы (пока не используется в коде) |
| `LINKS_FILE` | `links.txt` | Путь до файла ссылок |
| `DEFAULT_LIST_URL` | пусто | Резервный URL (зарезервировано) |
| `OUTPUT_DIR` | `configs` | Директория результатов |
| `OUTPUT_FILE` | `white-list_available` | Базовое имя файлов |
| `KEEP_ONLY_WHITELIST_FILES` | `true` | Оставлять только whitelist‑файлы |

### HTTP‑проверки (strict)

| Переменная | По умолчанию | Описание |
|---|---|---|
| `STRONG_STYLE_TEST` | `true` | Включить строгий режим |
| `STRONG_STYLE_TIMEOUT` | `12` | Таймаут строгой проверки (сек) |
| `STRONG_MAX_RESPONSE_TIME` | `3` | Максимум времени ответа (сек) |
| `STRONG_DOUBLE_CHECK` | `true` | Повторная проверка |
| `STRONG_ATTEMPTS` | `3` | Количество попыток |
| `REQUIRE_HTTPS` | `true` | Требовать HTTPS |
| `VERIFY_HTTPS_SSL` | `false` | Проверять SSL‑сертификаты |
| `TEST_URLS` | `http://www.google.com/generate_204,http://www.cloudflare.com/cdn-cgi/trace` | HTTP URL через запятую |
| `TEST_URLS_HTTPS` | `https://www.gstatic.com/generate_204` | HTTPS URL через запятую |
| `REQUESTS_PER_URL` | `2` | Количество запросов на URL |
| `MIN_SUCCESSFUL_REQUESTS` | `2` | Минимум успешных запросов |
| `MIN_SUCCESSFUL_URLS` | `2` | Минимум успешных URL |
| `REQUEST_DELAY` | `0.1` | Задержка между запросами (сек) |
| `CONNECT_TIMEOUT` | `6` | Таймаут соединения (сек) |
| `CONNECT_TIMEOUT_SLOW` | `15` | Таймаут медленного соединения (сек) |
| `MAX_RESPONSE_TIME` | `6` | Максимум времени ответа (сек) |
| `MAX_LATENCY_MS` | `2000` | Максимальная задержка (мс) |
| `MAX_RETRIES` | `1` | Количество ретраев |
| `RETRY_DELAY_BASE` | `0.5` | Базовая задержка ретрая |
| `RETRY_DELAY_MULTIPLIER` | `2.0` | Множитель задержки |
| `STABILITY_CHECKS` | `2` | Проверок стабильности |
| `STABILITY_CHECK_DELAY` | `2.0` | Задержка стабильности (сек) |

### Воркеры и порты

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MAX_WORKERS` | `200` | Максимум воркеров |
| `BASE_PORT` | `20000` | Базовый порт SOCKS |

### Бинарники движков

| Переменная | По умолчанию | Описание |
|---|---|---|
| `XRAY_PATH` | пусто | Путь к `xray` |
| `HYSTERIA_PATH` | пусто | Путь к `hysteria` |
| `XRAY_STARTUP_WAIT` | `1.2` | Время ожидания старта Xray (сек) |
| `XRAY_STARTUP_POLL_INTERVAL` | `0.2` | Интервал проверки Xray (сек) |
| `ENGINE_MODE` | `real` | `real` или `stub` |

### Egress

| Переменная | По умолчанию | Описание |
|---|---|---|
| `EGRESS_MODE` | `enforced` | `enforced`, `off`, `iptables`, `linux-netns`, `docker` |
| `EGRESS_BACKEND` | `native` | `native` (iptables) или `docker` |
| `EGRESS_ALLOW_OFF` | `false` | Установить `true`, чтобы разрешить `EGRESS_MODE=off` |
| `CIDR_WHITELIST_URL` | `https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt` | URL для CIDR‑списка |
| `CIDR_WHITELIST_FILE` | пусто | Локальный файл CIDR (имеет приоритет над URL) |

### Speedtest

| Переменная | По умолчанию | Описание |
|---|---|---|
| `SPEED_TEST_ENABLED` | `true` | Включить speedtest |
| `SPEED_TEST_TIMEOUT` | `2` | Таймаут speedtest (сек) |
| `SPEED_TEST_MODE` | `latency` | Режим speedtest |
| `SPEED_TEST_METRIC` | `latency` | Метрика speedtest |
| `SPEED_TEST_REQUESTS` | `5` | Количество запросов |
| `SPEED_TEST_URL` | `https://www.gstatic.com/generate_204` | URL для speedtest |
| `SPEED_TEST_WORKERS` | `200` | Воркеры speedtest |
| `SPEED_TEST_DOWNLOAD_TIMEOUT` | `30` | Таймаут загрузки (сек) |
| `SPEED_TEST_DOWNLOAD_URL_SMALL` | `https://speed.cloudflare.com/__down?bytes=250000` | Малый файл |
| `SPEED_TEST_DOWNLOAD_URL_MEDIUM` | `https://speed.cloudflare.com/__down?bytes=1000000` | Средний файл |
| `MIN_SPEED_THRESHOLD_MBPS` | `2.5` | Минимальная скорость (Мбит/с) |
| `SPEED_TEST_DOWNLOAD_CHUNKSIZE` | `32768` | Размер чанка загрузки |

### Re-check / notworkers

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RECHECK_PREVIOUS_WHITELISTS` | `true` | Подмешивать предыдущий whitelist |
| `USE_NOTWORKERS` | `true` | Использовать файл `notworkers` |

---

## Бинарники движков

- **Xray** используется для `vless://`, `vmess://`, `trojan://`, `ss://`
- **Hysteria** используется для `hysteria://`, `hysteria2://`, `hy2://`

### Автоматическая загрузка

Если бинарник не найден в `$PATH`, он будет **автоматически загружен** из официального
GitHub-релиза и сохранён в `~/.cache/white_chek/bin`:

| Платформа | Архитектура | Поддержка |
|---|---|---|
| Linux | x86_64 | ✅ |
| Linux | arm64 / aarch64 | ✅ |
| Windows | x64 | ✅ |
| macOS | любая | ❌ (установите вручную) |

После загрузки SHA-256 дайджест бинарника проверяется по файлу с GitHub-релиза.
При несовпадении хеша — ошибка с чётким сообщением.
Файлы кешируются и повторно не загружаются при следующих запусках.

Переопределить путь можно через `XRAY_PATH` / `HYSTERIA_PATH`
или флаги `--xray-path` / `--hysteria-path`.

---

## Зависимости

```
httpx[socks]>=0.27.0
pydantic>=2.6.0
rich>=13.7.0
pyyaml>=6.0.1
typing-extensions>=4.9.0
```
