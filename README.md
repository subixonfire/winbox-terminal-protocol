# MikroTik WinBox Terminal Client

A pure Python implementation of the MikroTik WinBox terminal protocol — encrypted CLI access to RouterOS devices over TCP port 8291.

> **Note:** This implements the WinBox **terminal (CLI) protocol** — the same text-based interface as WinBox app's "New Terminal" window. The graphical/GUI portion of the WinBox protocol is not implemented.

## What is the WinBox Terminal Protocol?

The WinBox protocol (TCP port 8291) is MikroTik's proprietary management protocol. While the WinBox desktop application uses it for GUI-based router management, the same port also exposes a terminal session — a full RouterOS CLI, encrypted with AES-128-CBC.

This project implements only the terminal portion, providing:
- An encrypted alternative to plaintext Telnet
- Access through the same port as WinBox GUI (almost always enabled)
- Full RouterOS CLI with command history and tab completion

## Features

- **EC-SRP5 authentication** (RouterOS >= 6.43) — modern elliptic-curve secure password verification
- **Legacy MD5 authentication** (RouterOS < 6.43) — challenge-response for older firmware
- **AES-128-CBC encryption** — all terminal traffic is encrypted after authentication
- **M2 binary protocol** — full implementation of MikroTik's M2 message format
- **Interactive terminal** with proper TTY handling
- **Terminal resize** (SIGWINCH) — automatically updates remote terminal dimensions
- **Self-contained** — single Python file

## Setup

```bash
git clone https://github.com/subixonfire/winbox-terminal-protocol.git
cd winbox-terminal-protocol
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome ecdsa
```

## Usage

### Connect to a router

```bash
python3 winbox_terminal_client.py 192.168.88.1 -u admin -p yourpassword
```

### With custom port

```bash
python3 winbox_terminal_client.py 192.168.88.1 --port 8291 -u admin -p yourpassword
```

### Exit the session

Press `Ctrl+]` to disconnect.

## Protocol Overview

| Component | Detail |
|-----------|--------|
| Transport | TCP port 8291 |
| Encryption | AES-128-CBC (after authentication) |
| Auth (modern) | EC-SRP5 (RouterOS >= 6.43) |
| Auth (legacy) | MD5 challenge-response |
| Message format | M2 binary TLV (Type-Length-Value) |
| Terminal type | vt102 |

### How It Works

1. **TCP connection** to port 8291
2. **Authentication** via EC-SRP5 or MD5 challenge-response
3. **Encryption setup** — AES-128-CBC keys derived from auth handshake
4. **Terminal session** — opens a vt102 terminal with configurable dimensions
5. **Bidirectional I/O** — stdin/stdout mapped to encrypted terminal stream

## Technical Details

### M2 Message Format

The WinBox protocol uses a proprietary binary format called M2. Messages consist of:
- 2-byte magic header (`M2`)
- Sequence of TLV (Type-Length-Value) encoded fields
- System keys (routing, commands, request IDs)
- User keys (application-specific data)

### Encryption

After authentication, all traffic is encrypted:
- **Cipher**: AES-128-CBC
- **Key derivation**: From the EC-SRP5 shared secret
- **Frame format**: Length-prefixed encrypted blocks with sequence tracking

## Known Limitations

- Only the terminal (CLI) protocol is implemented, not the GUI protocol
- No certificate-based authentication support
- Single-session only (no multiplexing)

## Acknowledgments and References

All protocol implementations are based on reverse engineering. This project builds on research from:

- [MarginResearch/mikrotik_authentication](https://github.com/MarginResearch/mikrotik_authentication) — Research and proof-of-concept implementations of MikroTik's EC-SRP5 authentication protocol. Provided the elliptic curve cryptography and session key derivation used in this client.

## License

MIT
