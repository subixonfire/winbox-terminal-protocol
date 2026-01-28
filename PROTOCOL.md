# WinBox M2 Protocol Specification

## Overview

The WinBox protocol operates over TCP port 8291. It supports two
authentication methods:

- **EC-SRP5** (RouterOS >= 6.43): Elliptic curve Secure Remote Password,
  followed by AES-128-CBC encrypted message transport.
- **Old MD5 challenge-response** (RouterOS < 6.43): Unencrypted M2 messages
  with MD5-based password hashing.

All application messages use the "M2" binary TLV format.

---

## 1. Connection & Authentication (EC-SRP5)

### Phase 1: Public Key Exchange

**Client -> Server:**
```
[length: 1 byte] [0x06] [username + \x00] [public_key: 32 bytes] [parity: 1 byte]
```

**Server -> Client:**
```
[length: 1 byte] [0x06] [server_public_key: 32 bytes] [parity: 1 byte] [salt: 16 bytes]
```

### Phase 2: Confirmation

**Client -> Server:**
```
[length: 1 byte] [0x06] [client_confirmation: 32 bytes (SHA-256)]
```

**Server -> Client:**
```
[length: 1 byte] [0x06] [server_confirmation: 32 bytes (SHA-256)]
```

### Key Derivation

After authentication, derive 4 keys from the shared secret:
- `send_aes_key` (16 bytes) - Client->Server AES-128-CBC key
- `receive_aes_key` (16 bytes) - Server->Client AES-128-CBC key
- `send_hmac_key` (16 bytes) - Client->Server HMAC-SHA1 key
- `receive_hmac_key` (16 bytes) - Server->Client HMAC-SHA1 key

Uses HKDF with magic strings:
- `"On the client side, this is the send key; on the server side, it is the receive key."`
- `"On the client side, this is the receive key; on the server side, it is the send key."`

### Elliptic Curve

Uses Curve25519 in Weierstrass form:
- `p = 2^255 - 19`
- Montgomery A = 486662
- Generator: lift_x(9, even parity)
- Order `r = 2^252 + 27742317777372353535851937790883648493`
- Cofactor h = 8

---

## 1b. Old Authentication (MD5 Challenge-Response, pre-6.43)

RouterOS versions before 6.43 use an unencrypted MD5 challenge-response
authentication over the M2 message protocol. There is no encryption layer —
all M2 messages are sent in plaintext using tag 0x01 framing.

### Detection

The client sends an EC-SRP5 init (tag 0x06). Old RouterOS ignores it entirely
(no response). After a timeout (e.g., 3 seconds), the client reconnects and
uses the old authentication flow.

### Step 1: Request List (get session ID)

```
M2
  SYS_TO     = [2, 2]       (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]  (u32_array, 0xFF)
  SYS_CMD    = 7             (u32, 0xFF)
  SYS_REQUEST = true         (bool, 0xFF)
  SYS_REQID  = 1             (u8, 0xFF)
  key_1      = "list"        (string, 0x00)
```

**Response** contains `SESSION_ID` (0xFE0001, u8) — save this for all
subsequent messages.

### Step 2a: Challenge Setup

```
M2
  SYS_TO     = [2, 2]       (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]  (u32_array, 0xFF)
  SYS_CMD    = 5             (u32, 0xFF)
  SYS_REQUEST = true         (bool, 0xFF)
  SYS_REQID  = 2             (u8, 0xFF)
  SESSION_ID = <sid>         (u8, 0xFE)
```

Response may or may not arrive — drain and discard.

### Step 2b: Request Challenge (get salt)

```
M2
  SYS_TO     = [13, 4]      (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]  (u32_array, 0xFF)
  SYS_CMD    = 4             (u32, 0xFF)
  SYS_REQUEST = true         (bool, 0xFF)
  SYS_REQID  = 3             (u8, 0xFF)
  SESSION_ID = <sid>         (u8, 0xFE)
```

**Response** contains `key_9` (raw, 0x00) — the 16-byte salt.

### Step 3: Login

Compute: `hashed = 0x00 + MD5(0x00 + password_utf8 + salt)`

```
M2
  SYS_TO     = [13, 4]      (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]  (u32_array, 0xFF)
  SYS_CMD    = 1             (u32, 0xFF)
  SYS_REQUEST = true         (bool, 0xFF)
  SYS_REQID  = 4             (u8, 0xFF)
  SESSION_ID = <sid>         (u8, 0xFE)
  key_1      = <username>    (string, 0x00)
  key_9      = <salt>        (raw, 0x00)
  key_10     = <hashed>      (raw, 0x00)   -- 17 bytes (0x00 + MD5)
```

**Response**: Check `SYS_STATUS` (0xFF0008). Value 0 = success,
non-zero = wrong username or password.

### After Old Auth

After successful old auth, the same M2 message flow applies (initial
request, meptyLogin, meptyData), but all messages are sent **unencrypted**
using tag 0x01 framing. The `SESSION_ID` from the auth phase must be
included in subsequent messages.

---

## 2. Frame Format

After authentication, messages are framed using a chunked format.
Both encrypted (tag 0x06) and unencrypted (tag 0x01) protocols use
the same chunk structure.

### Chunk Structure

```
Chunk: [chunk_len: 1 byte] [tag: 1 byte] [payload: chunk_len bytes]
```

- **First chunk tag**: `0x06` (encrypted) or `0x01` (unencrypted)
- **Continuation tag**: `0xFF` (both protocols)
- `chunk_len = 0xFF`: full chunk (255 payload bytes, more chunks follow)
- `chunk_len < 0xFF`: last chunk (this many payload bytes)

### Assembled Payload

After reassembling all chunks (stripping headers, concatenating payloads):

- **Encrypted (tag 0x06)**: `[enc_length: 2 BE] [IV: 16] [ciphertext]`
- **Unencrypted (tag 0x01)**: `[body_length: 2 BE] [M2 message body]`

### Encrypted Frame Details (tag 0x06)

For encrypted connections (EC-SRP5), the assembled payload contains:

```
[enc_length: 2 bytes BE] [IV: 16 bytes] [ciphertext: N bytes]
```

### Encryption (Client -> Server)

1. Compute HMAC-SHA1 over plaintext M2 message
2. Append HMAC (20 bytes) to message
3. Compute `pad_byte = 0x0F - (len(msg+hmac) % 0x10)` (range 0x00–0x0F)
4. Append `pad_byte + 1` bytes, each with value `pad_byte`
   (This is NOT standard PKCS7. When `pad_byte = 0`, one 0x00 byte is added.
   The result is always block-aligned without producing any byte > 0x0F.)
5. Encrypt with AES-128-CBC using random 16-byte IV

For small messages: first chunk's `chunk_len = encrypted_length + 0x12`
(includes 2-byte enc_length + 16-byte IV).

### Decryption (Server -> Client)

1. Reassemble chunks (strip chunk headers, concatenate payloads)
2. Extract `enc_length` (2 bytes BE), IV (16 bytes), ciphertext (remaining)
3. AES-128-CBC decrypt with `receive_aes_key` and IV
4. Strip padding: if last byte != 0, strip N bytes where N = last byte value;
   then strip the pad indicator byte (always 1 byte)
5. Split: plaintext = decrypted[:-20], hmac = decrypted[-20:]
6. Verify HMAC-SHA1 over plaintext using `receive_hmac_key`

---

## 3. M2 Message Format

All decrypted messages start with the ASCII bytes `M2` (0x4D 0x32), followed
by a sequence of TLV (Type-Length-Value) entries.

### TLV Entry Format

Each entry is 4 header bytes followed by type-specific data:

```
[key_low: 1 byte] [key_high: 1 byte] [namespace: 1 byte] [type: 1 byte] [value...]
```

- **key_low, key_high**: Little-endian key ID within the namespace
- **namespace**: Identifies the key category
- **type**: Data type indicator

### Namespaces

| Namespace | Hex  | Purpose |
|-----------|------|---------|
| System    | 0xFF | Protocol control (routing, commands, request IDs) |
| Session   | 0xFE | Session management (session IDs, session config) |
| User      | 0x00 | Application data (terminal data, parameters) |

### Full Key Encoding

A "full key" is `(namespace << 16) | (key_high << 8) | key_low`:
- `SYS_TO`      = 0xFF0001
- `SYS_FROM`    = 0xFF0002
- `SYS_REQUEST` = 0xFF0005
- `SYS_REQID`   = 0xFF0006
- `SYS_CMD`     = 0xFF0007
- `SESSION_ID`  = 0xFE0001

### Data Types

| Type | Hex  | Size | Description |
|------|------|------|-------------|
| bool_false | 0x00 | 0 bytes | Boolean false (no value bytes) |
| bool_true  | 0x01 | 0 bytes | Boolean true (no value bytes) |
| u32        | 0x08 | 4 bytes | Unsigned 32-bit integer (little-endian) |
| u8         | 0x09 | 1 byte  | Unsigned 8-bit integer |
| u64        | 0x10 | 8 bytes | Unsigned 64-bit integer (little-endian) |
| string_s   | 0x21 | 1+N    | String: 1-byte length + UTF-8 data |
| string_l   | 0x20 | 2+N    | String: 2-byte LE length + UTF-8 data |
| raw_s      | 0x31 | 1+N    | Raw bytes: 1-byte length + data |
| raw_l      | 0x30 | 2+N    | Raw bytes: 2-byte LE length + data |
| msg_s      | 0x29 | 1+N    | Embedded M2 message: 1-byte length + M2 data |
| msg_l      | 0x28 | 2+N    | Embedded M2 message: 2-byte LE length + M2 data |
| u32_array  | 0x88 | 2+4*N  | Array of u32: 2-byte LE count + N u32 values |
| str_array  | 0xA0 | 2+var  | Array of strings: 2-byte LE count, each entry is 2-byte LE length + data |
| msg_array  | 0xA8 | 2+var  | Array of messages: 2-byte LE count, each entry is 2-byte LE length + data |

**Small vs Large length types**: Types with bit 0 set (0x21, 0x31, 0x29)
use 1-byte length (max 255). Types without bit 0 (0x20, 0x30, 0x28)
use 2-byte LE length (max 65535).

---

## 4. System Keys Reference

| Key | Full ID | Type | Description |
|-----|---------|------|-------------|
| SYS_TO | 0xFF0001 | u32_array | Destination handler path (e.g., [76] or [13,4]) |
| SYS_FROM | 0xFF0002 | u32_array | Source handler path (e.g., [0, source_id]) |
| SYS_REQUEST | 0xFF0005 | bool | True if this is a request (expects response) |
| SYS_REQID | 0xFF0006 | u8/u32 | Request identifier (for matching responses) |
| SYS_CMD | 0xFF0007 | u8/u32 | Command code |
| SYS_STATUS | 0xFF0008 | u8/u32 | Response status |
| SESSION_ID | 0xFE0001 | u8 | Terminal session identifier |
| FE000C | 0xFE000C | u8 | Session config parameter |

### Known Handler Paths

| Path | Handler |
|------|---------|
| [13, 4] | System info / initial capabilities |
| [76] | mepty (terminal PTY handler) |
| [120] | Session/login handler |
| [24, 0] | Management data (GUI state) |
| [24, 1] | Management session |
| [24, 2] | Management session (alternate) |

### Known Commands

| Command | Hex | Description |
|---------|-----|-------------|
| cmdGet | 7 (0x07) | Get data/capabilities |
| cmdOpen | 5 (0x05) | Open handler/session |
| meptyLogin | 655461 (0x0A0065) | Open terminal PTY session |
| meptyData | 655463 (0x0A0067) | Terminal data exchange |
| 16646157 (0xFE000D) | GUI management polling |

---

## 5. Terminal Session Protocol

### Step 1: Initial Request (capabilities)

```
M2
  SYS_TO     = [13, 4]     (u32_array, 0xFF)
  SYS_FROM   = [0, src_id] (u32_array, 0xFF)
  SYS_REQUEST = true        (bool, 0xFF)
  SYS_REQID  = 0            (u8, 0xFF)
  SYS_CMD    = 7            (u8, 0xFF)
```

**Response** contains system info: board name, architecture, RouterOS version,
license level, and a `msg-proxy-X.Y.Z` version string in a string array (0xA0).

### Step 2: meptyLogin (open terminal)

```
M2
  SYS_TO     = [76]         (u32_array, 0xFF)    -- mepty handler
  SYS_FROM   = [0, src_id]  (u32_array, 0xFF)
  SYS_REQUEST = true         (bool, 0xFF)
  key_5      = <columns>     (u8, 0x00)           -- terminal width (e.g., 80)
  key_6      = <rows>        (u8, 0x00)           -- terminal height (e.g., 24)
  key_8      = 0             (u8, 0x00)           -- connection type
  SYS_REQID  = <N>           (u8, 0xFF)
  SYS_CMD    = 655461        (u32, 0xFF)          -- 0x0A0065 meptyLogin
  key_11     = M2{key_1=0}   (embedded msg, 0x00) -- inner msg with key_1=0
  key_7      = "vt102"       (string, 0x00)       -- terminal type
  key_1      = <password>    (string, 0x00)       -- user password
```

### Step 3: meptyLogin Response

```
M2
  SYS_TO     = [0, src_id]  (u32_array, 0xFF)
  SYS_FROM   = [76]          (u32_array, 0xFF)
  str_array  = ["msg-proxy-7.18.2"]  (0xA0, 0xFF)
  SESSION_ID = <sid>         (u8, 0xFE)           -- ** SAVE THIS **
  SYS_STATUS = 2             (u8, 0xFF)           -- 0xFF0003
  SYS_REQID  = <N>           (u8, 0xFF)           -- matches request
```

### Step 4: Ready Signal (no data)

```
M2
  SYS_TO     = [76]          (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]   (u32_array, 0xFF)
  key_3      = <counter>      (u32, 0x00)         -- byte counter (starts at 0)
  SESSION_ID = <sid>          (u8, 0xFE)
  SYS_CMD    = 655463         (u32, 0xFF)         -- 0x0A0067 meptyData
```

No `key_2` field - this signals the client is ready to receive output.

### Step 5: Server Sends Terminal Output

```
M2
  SYS_TO     = [0, src_id]   (u32_array, 0xFF)
  SYS_FROM   = [76]           (u32_array, 0xFF)
  str_array  = [...]           (0xA0, 0xFF)       -- proxy version
  SESSION_ID = <sid>           (u8, 0xFE)
  SYS_CMD    = 655463          (u32, 0xFF)        -- meptyData
  key_2      = <terminal data> (raw, 0x00)        -- VT102 output bytes
```

The `key_2` raw data contains terminal output including ANSI escape
sequences. The data type is `0x31` (1-byte length, up to 255 bytes)
or `0x30` (2-byte LE length, up to 65535 bytes).

### Step 6: Client Sends Keystroke

```
M2
  SYS_TO     = [76]           (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]    (u32_array, 0xFF)
  key_3      = <counter>       (u32, 0x00)        -- running byte counter
  SESSION_ID = <sid>           (u8, 0xFE)
  SYS_CMD    = 655463          (u32, 0xFF)        -- meptyData
  key_2      = <keystroke(s)>  (raw, 0x00)        -- input bytes
```

The `key_3` counter tracks total bytes sent by the client. Increment
by the number of bytes in each `key_2` payload.

### Step 7: Client Sends Flow-Control ACK

After receiving terminal output, the client must send an ACK to allow the
server to continue sending. Without ACKs, the server stops after ~8 KB.

```
M2
  SYS_TO     = [76]           (u32_array, 0xFF)
  SYS_FROM   = [0, src_id]    (u32_array, 0xFF)
  key_3      = <recv_counter>  (u32, 0x00)        -- total RECEIVED bytes
  SESSION_ID = <sid>           (u8, 0xFE)
  SYS_CMD    = 655463          (u32, 0xFF)        -- meptyData
```

No `key_2` field — same format as the ready signal (Step 4), but `key_3`
contains the cumulative count of bytes received from the server (sum of
all `key_2` payload lengths). The server uses this for flow control: it
buffers ~8 KB of terminal output and pauses until the client ACKs.

The client should send an ACK after each burst of received messages.

---

## 6. Byte-Level Examples

### Initial Request (hex)

```
4d 32                           -- M2 header
01 00 ff 88 02 00               -- SYS_TO: u32_array, count=2
  0d 00 00 00 04 00 00 00       --   [13, 4]
02 00 ff 88 02 00               -- SYS_FROM: u32_array, count=2
  00 00 00 00 01 00 00 00       --   [0, 1]
05 00 ff 01                     -- SYS_REQUEST: bool true
06 00 ff 09 00                  -- SYS_REQID: u8 = 0
07 00 ff 09 07                  -- SYS_CMD: u8 = 7
```

### Keystroke 't' (0x74)

```
4d 32                           -- M2 header
01 00 ff 88 01 00               -- SYS_TO: u32_array, count=1
  4c 00 00 00                   --   [76]
02 00 ff 88 02 00               -- SYS_FROM: u32_array, count=2
  00 00 00 00 ad 01 00 00       --   [0, 429]
03 00 00 08 98 02 00 00         -- key_3: u32 = 664 (byte counter)
01 00 fe 09 1c                  -- SESSION_ID: u8 = 28
07 00 ff 08 67 00 0a 00         -- SYS_CMD: u32 = 0x000A0067
02 00 00 31 01 74               -- key_2: raw, len=1, data=0x74 ('t')
```

### Terminal Output (banner fragment)

```
4d 32
01 00 ff 88 02 00               -- SYS_TO: [0, 428]
  00 00 00 00 ac 01 00 00
02 00 ff 88 01 00               -- SYS_FROM: [76]
  4c 00 00 00
1c 00 ff a0 01 00 10 00         -- str_array: 1 entry, 16 bytes
  6d 73 67 2d 70 72 6f 78 79 2d 37 2e 31 38 2e 32  -- "msg-proxy-7.18.2"
01 00 fe 09 1b                  -- SESSION_ID: u8 = 27
07 00 ff 08 67 00 0a 00         -- SYS_CMD: u32 = 655463
02 00 00 31 13                  -- key_2: raw, len=19
  50 72 65 73 73 20 46 31 20 66 6f 72 20 68 65 6c 70 0d 0a
                                -- "Press F1 for help\r\n"
```
