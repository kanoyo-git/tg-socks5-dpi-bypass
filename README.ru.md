[English](README.md) | [Русский](README.ru.md)

# SOCKS5 DPI Bypass

LD_PRELOAD библиотека для обхода DPI при использовании SOCKS5 прокси в Telegram/AyuGram.

## Принцип работы

Библиотека перехватывает socket-вызовы (`connect`, `send`, `recv`, `write`) и применяет техники обхода DPI:

1. **Фрагментация SOCKS5 handshake** - побайтовая отправка с random jitter (1-7ms). DPI не обнаруживает сигнатуру `05 01/02 xx` в одном TCP-сегменте.

2. **Фрагментация SOCKS5 CONNECT** - побайтовая отправка запроса соединения. DPI не видит целевой адрес/домен.

3. **Адаптивный split первого payload** - первый пакет после SOCKS5 CONNECT режется по протокольным границам (TLS record/SNI, HTTP method/Host) или по рандомизированным смещениям. DPI заметно сложнее собрать исходную сигнатуру.

```
Telegram → [hooked send/recv] → [DPI bypass] → SOCKS5 сервер
```

## Сборка

Требования:
- gcc
- заголовки POSIX

```bash
make
```

Результат: `socks5_dpi_bypass.so`

## Установка

```bash
sudo make install
```

Устанавливает в `/usr/local/lib/socks5_dpi_bypass.so`

## Использование

### LD_PRELOAD

```bash
LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram
```

Или для Telegram Desktop:

```bash
LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so Telegram
```

### Desktop файл (опционально)

Отредактируйте `.desktop` файл Telegram/AyuGram (обычно в `~/.local/share/applications/` или `/usr/share/applications/`):

```ini
[Desktop Entry]
...
Exec=env LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram -- %u
...
```

**Важно:** Если в desktop файле есть `DBusActivatable=true`, измените на `DBusActivatable=false`. DBus activation игнорирует строку `Exec` и LD_PRELOAD не сработает.

### Алиас в .bashrc

Добавьте в `~/.bashrc`:

```bash
alias ayugram='LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram'
alias telegram='LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so Telegram'
```

## Настройка прокси в Telegram

1. Откройте Settings → Data and Storage → Proxy Settings
2. Добавьте SOCKS5 прокси (или нажмите `t.me/socks?server=...`)
3. Библиотека автоматически применит DPI bypass к соединению

## Удаление

```bash
sudo make uninstall
```

## Алгоритм работы

Машина состояний:

1. `STATE_NONE` → детект SOCKS5 greeting (`05 xx methods`) → побайтовая отправка
2. `STATE_SOCKS5_GREETING` → детект auth или CONNECT → побайтовая отправка
3. `STATE_SOCKS5_AUTH` → детект CONNECT → побайтовая отправка
4. `STATE_SOCKS5_CONNECT_SENT` → ожидание ответа сервера
5. `STATE_INITIAL_BURST` → разбиение первого payload после CONNECT по TLS/HTTP-aware или generic DPI-эвристикам
6. `STATE_PIPE` → прозрачная передача данных

## Ограничения

- Только SOCKS5 (не HTTP proxy)
- Только IPv4 адреса proxy
- Не для localhost proxy

## Лицензия

MIT
