# NisHack — School PC Monitoring Agent

A lightweight Rust agent that runs on school Windows PCs to enforce usage policies.

## Features

| Feature | How it works |
|---|---|
| **Process banning** | Scans running processes every N seconds, kills anything on the ban list (Roblox, Steam, Discord, etc.) |
| **Website detection** | Checks the DNS cache + browser window titles for banned domains (Windows, macOS, Linux) |
| **Violation logging** | Every violation is timestamped and pushed to Redis with the hostname + username |
| **Heartbeat / IP sharing** | Pushes its IP, hostname, and port to Redis so a central dashboard always knows which PCs are online |
| **HTTP API** | Exposes `/health`, `/info`, `/violations`, `/config` for remote queries |
| **Cross-platform** | Works on Windows, macOS, and Linux with platform-specific detection methods |

## Quick start

```bash
# Build (release, small binary)
cargo build --release

# Copy the binary + config to the target PC
# Edit config.toml to point at your Redis server

# Run
.\nishack.exe
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check + uptime |
| GET | `/info` | CPU, RAM, OS, username, process count |
| GET | `/violations?count=50` | Recent violations for this PC |
| GET | `/config` | Current ban lists and scan interval |

## Redis Keys

All keys are prefixed with the `key_prefix` from config (default: `nishack`).

| Key pattern | Type | Description |
|---|---|---|
| `nishack:heartbeat:<hostname>` | String (TTL 90s) | Last heartbeat JSON |
| `nishack:agents` | Set | All known `hostname\|ip\|port` entries |
| `nishack:violations:<hostname>` | List | Violation history (newest first) |
| `nishack:violation_count:<hostname>` | Integer | Running violation counter |

## Configuration

Edit `config.toml` next to the executable. See the file for all options.

## Platform-Specific Features

### Windows
- **DNS Cache**: Uses `ipconfig /displaydns` to detect visited domains
- **Window Titles**: Uses PowerShell to enumerate all window titles
- **DNS Flush**: Uses `ipconfig /flushdns`

### macOS
- **DNS Cache**: Uses `dscacheutil -cachedump` (may be limited on newer macOS versions)
- **Window Titles**: Uses AppleScript to query browser and application windows
- **DNS Flush**: Uses `dscacheutil -flushcache` or `killall -HUP mDNSResponder`

### Linux
- **DNS Cache**: Not supported (no standard DNS cache command)
- **Window Titles**: Not supported
- **Process Monitoring**: Fully supported

**Note**: Website detection works best on Windows. On macOS, window title scanning is the primary detection method. On Linux, only process monitoring is available.

## Building for Windows from macOS/Linux

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```
