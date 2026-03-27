[English](README.md) | [Русский](README.ru.md)

# SOCKS5 DPI Bypass

LD_PRELOAD library for bypassing DPI when using SOCKS5 proxy in Telegram/AyuGram.

## How it works

The library intercepts socket calls (`connect`, `send`, `recv`, `write`) and applies DPI bypass techniques:

1. **SOCKS5 handshake fragmentation** - byte-by-byte sending with random jitter (1-7ms). DPI cannot detect `05 01/02 xx` signature in a single TCP segment.

2. **SOCKS5 CONNECT fragmentation** - byte-by-byte sending of connection request. DPI cannot see target address/domain.

3. **TLS ClientHello split** - splitting first TLS packet into two segments. SNI is split between segments, DPI cannot read hostname.

```
Telegram → [hooked send/recv] → [DPI bypass] → SOCKS5 server
```

## Building

Requirements:
- gcc
- POSIX headers

```bash
make
```

Output: `socks5_dpi_bypass.so`

## Installation

```bash
sudo make install
```

Installs to `/usr/local/lib/socks5_dpi_bypass.so`

## Usage

### LD_PRELOAD

```bash
LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram
```

Or for Telegram Desktop:

```bash
LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so Telegram
```

### Desktop file (optional)

Edit your Telegram/AyuGram `.desktop` file (usually in `~/.local/share/applications/` or `/usr/share/applications/`):

```ini
[Desktop Entry]
...
Exec=env LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram -- %u
...
```

**Important:** If the desktop file has `DBusActivatable=true`, change it to `DBusActivatable=false`. DBus activation bypasses the `Exec` line and LD_PRELOAD won't work.

### .bashrc alias

Add to `~/.bashrc`:

```bash
alias ayugram='LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so AyuGram'
alias telegram='LD_PRELOAD=/usr/local/lib/socks5_dpi_bypass.so Telegram'
```

## Configuring proxy in Telegram

1. Open Settings → Data and Storage → Proxy Settings
2. Add SOCKS5 proxy (or click `t.me/socks?server=...`)
3. The library will automatically apply DPI bypass to the connection

## Uninstall

```bash
sudo make uninstall
```

## Algorithm

State machine:

1. `STATE_NONE` → detect SOCKS5 greeting (`05 xx methods`) → byte-by-byte send
2. `STATE_SOCKS5_GREETING` → detect auth or CONNECT → byte-by-byte send
3. `STATE_SOCKS5_AUTH` → detect CONNECT → byte-by-byte send
4. `STATE_SOCKS5_CONNECT_SENT` → wait for server response
5. `STATE_TLS_FIRST` → check first packet for TLS → split if TLS
6. `STATE_PIPE` → transparent data forwarding

## Limitations

- SOCKS5 only (not HTTP proxy)
- IPv4 proxy addresses only
- Not for localhost proxy

## License

MIT