# alostcp

Zero-friction, **authenticated** end-to-end encrypted TCP for Go. One password, one import, full protection.

```bash
go get github.com/guno1928/alostcp
```

```go
import "github.com/guno1928/alostcp/core"
```

## Contents

- [Why alostcp?](#why-alostcp)
- [Quick start](#quick-start)
- [Usage](#usage)
- [API reference](#api-reference)
- [How it works](#how-it-works)
- [Wire format](#wire-format)
- [Benchmarks](#benchmarks)
- [Security notes](#security-notes)
- [Roadmap](#roadmap)
- [Requirements](#requirements)

---

## Why alostcp?

- **Authenticated encryption** -- Every message is sealed with **AEGIS-128L**, a modern AEAD cipher. You get confidentiality *and* integrity: any tampering with the ciphertext, the auth tag, or even the length header is detected and rejected.
- **Anti-MITM handshake** -- On connect, both sides prove they know the shared password before any data flows. Handshake frames are themselves AEGIS-authenticated.
- **Fast bulk throughput** -- A hand-written AEGIS-128L AES-NI assembly cipher, validated byte-for-byte against the reference implementation, with a zero-copy receive path and pooled buffers.
- **Timeouts built in** -- Context- and deadline-aware dialing, per-operation read/write deadlines, and fail-fast handling of dead connections.
- **Tiny surface** -- Connect, Listen, Send, Recv. No TLS config, no certificates, no PKI.
- **Cross-platform** -- Windows and Linux on amd64 (AES-NI required).

---

## Quick start

**Server**

```go
package main

import (
    "log"
    "github.com/guno1928/alostcp/core"
)

func main() {
    ln, err := core.Listen(9000, "shared-password")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()

    conn, err := ln.Accept()
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    msg, err := conn.RecvString()
    if err != nil {
        log.Fatal(err)
    }
    log.Println("received:", msg)
}
```

**Client**

```go
package main

import (
    "log"
    "github.com/guno1928/alostcp/core"
)

func main() {
    conn, err := core.Connect("127.0.0.1", 9000, "shared-password")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    if err := conn.SendString("hello server"); err != nil {
        log.Fatal(err)
    }
}
```

---

## Usage

### Binary send and receive

```go
conn, _ := core.Connect("127.0.0.1", 9000, "secret")
defer conn.Close()

conn.Send([]byte{0x01, 0x02, 0x03})

response, _ := conn.Recv()
```

### Wrong password is rejected at handshake

```go
// Server
ln, _ := core.Listen(9000, "correct-password")
conn, err := ln.Accept()
// err == nil only if the client proved it knows "correct-password"

// Client with wrong password
conn, err := core.Connect("127.0.0.1", 9000, "wrong-password")
// err != nil -- handshake fails: wrong key or MITM detected
```

### Concurrent echo server

```go
ln, _ := core.Listen(9000, "secret")
defer ln.Close()

for {
    conn, err := ln.Accept()
    if err != nil {
        continue
    }
    go func(c *core.Conn) {
        defer c.Close()
        for {
            msg, err := c.RecvString()
            if err != nil {
                return
            }
            c.SendString("echo: " + msg)
        }
    }(conn)
}
```

It is safe to call `Send`/`SendBuffered` from multiple goroutines and `Recv`/`RecvInto` from another; writes and reads are independently serialized.

### High-throughput streaming

```go
conn, _ := core.Connect("127.0.0.1", 9000, "secret")
defer conn.Close()

// Batch many small messages into fewer TCP segments
payload := make([]byte, 1024)
for i := 0; i < 10000; i++ {
    conn.SendBuffered(payload)
}
conn.Flush()
```

### Reusing a buffer on receive

`RecvInto` decrypts directly into a caller-supplied buffer (zero-copy, no per-message allocation for the payload):

```go
buf := make([]byte, 64*1024)
for {
    n, err := conn.RecvInto(buf)
    if err != nil {
        break
    }
    process(buf[:n])
}
```

If a message is larger than `buf`, `RecvInto` returns an error and the connection is poisoned (see below).

### Timeouts and deadlines

```go
import (
    "context"
    "time"

    "github.com/guno1928/alostcp/core"
)

// Bound the dial + handshake with a duration...
conn, err := core.ConnectTimeout("127.0.0.1", 9000, "secret", 5*time.Second)

// ...or with a context.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
conn, err = core.ConnectContext(ctx, "127.0.0.1", 9000, "secret")

// Per-operation deadlines (passthrough to the TCP socket):
conn.SetReadDeadline(time.Now().Add(2 * time.Second))
conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
conn.SetDeadline(time.Now().Add(2 * time.Second)) // both at once

// Bound how long Accept waits for a new connection:
ln.SetDeadline(time.Now().Add(time.Second))
```

> **Mid-frame timeouts are fatal.** If a `Send` or `Recv` exceeds its deadline partway through a frame, the AEGIS stream can no longer be resynchronized. The connection is *poisoned*: it is closed and every later operation returns `ErrConnBroken`. Treat a timed-out connection as dead and dial a new one. The plain `Connect` blocks indefinitely (unchanged); use the timeout/context variants to bound it.

---

## API reference

### Dialing

```go
func Connect(ip string, port int, password string) (*Conn, error)
func ConnectContext(ctx context.Context, ip string, port int, password string) (*Conn, error)
func ConnectTimeout(ip string, port int, password string, timeout time.Duration) (*Conn, error)
```

`Connect` blocks indefinitely. `ConnectContext` and `ConnectTimeout` bound **both** the TCP connect and the password handshake.

### Listening

```go
func Listen(port int, password string) (*Listener, error)

func (ln *Listener) Accept() (*Conn, error)
func (ln *Listener) SetDeadline(t time.Time) error  // bounds Accept; zero value clears
func (ln *Listener) Close() error
func (ln *Listener) Addr() net.Addr
```

### Connection

```go
// Sending
func (c *Conn) Send(data []byte) error          // seal + write + flush
func (c *Conn) SendBuffered(data []byte) error  // seal + buffer (no flush)
func (c *Conn) Flush() error                     // flush buffered writes
func (c *Conn) SendString(s string) error

// Receiving
func (c *Conn) Recv() ([]byte, error)            // returns a freshly allocated payload
func (c *Conn) RecvInto(buf []byte) (int, error) // zero-copy into buf; err if too small
func (c *Conn) RecvString() (string, error)

// Lifecycle & addressing
func (c *Conn) Close() error
func (c *Conn) LocalAddr() net.Addr
func (c *Conn) RemoteAddr() net.Addr

// Socket tuning
func (c *Conn) SetNoDelay(noDelay bool) error
func (c *Conn) SetDeadline(t time.Time) error
func (c *Conn) SetReadDeadline(t time.Time) error
func (c *Conn) SetWriteDeadline(t time.Time) error
```

### Errors

```go
var ErrConnClosed = errors.New("alostcp: connection closed") // returned after Close()
var ErrConnBroken = errors.New("alostcp: connection broken") // returned after a mid-frame I/O failure
```

A frame whose authentication tag does not verify, an oversized/invalid length, a short read/write, or a deadline hit mid-frame all *poison* the connection: it is closed and subsequent calls return `ErrConnBroken`. Use `errors.Is(err, core.ErrConnBroken)` to detect it.

---

## How it works

1. **Dial / Accept** -- A raw TCP socket is established (`TCP_NODELAY` set; `TCP_QUICKACK` on Linux).
2. **Anti-MITM handshake** -- The server generates a random one-time token (OTP) and sends it inside an AEGIS-sealed frame keyed by the shared password. The client decrypts it (an authentication failure here means wrong password or tampering), computes `SHA256(OTP || password)`, and returns it in another sealed frame. The server verifies with a constant-time comparison. If either side has the wrong password, the connection is dropped immediately.
3. **Per-session keying** -- Both sides derive two independent 128-bit IVs from `SHA256(password || OTP || direction)`, one per direction.
4. **Encrypted traffic** -- After the handshake, every `Send` seals the payload with AEGIS-128L and transmits `[4-byte length][ciphertext ‖ 16-byte tag]`. The 4-byte length prefix is bound into the tag as **associated data**, so length tampering is detected too. Each direction maintains its own 128-bit counter nonce (seeded from its IV, incremented per message); the nonce is implicit and never sent on the wire. Every `Recv` reads the frame, verifies the tag, and decrypts.

### Cipher: AEGIS-128L (AEAD)

alostcp uses **AEGIS-128L**, a high-performance authenticated cipher built on the AES round function. Unlike a raw stream cipher, AEGIS produces a 128-bit authentication tag per message — tampering is cryptographically detected rather than silently decrypted into garbage.

The production cipher is a **hand-written AES-NI assembly implementation** (`aegis128l_amd64.s`) that keeps all eight 128-bit state words in XMM registers across the whole message, handling init, associated-data absorption, encryption, and finalization in a single call. It is validated **byte-for-byte against the reference implementation** ([`github.com/ericlagergren/aegis`](https://github.com/ericlagergren/aegis)) across all message/AD sizes plus thousands of randomized differential iterations, and its separate-tag API enables a **zero-copy in-place receive** path.

---

## Wire format

**Handshake frame**

```
[ 4 bytes ] big-endian length of the remainder
[16 bytes ] AEGIS nonce (random per frame)
[ N bytes ] AEGIS-sealed payload (plaintext + 16-byte tag)
```

**Data frame** (post-handshake)

```
[ 4 bytes ] big-endian length L = len(plaintext) + 16   (authenticated as associated data)
[ L bytes ] ciphertext ‖ 16-byte AEGIS tag
```

The per-message nonce is an implicit 128-bit counter (seeded from the handshake-derived IV) and is **not** transmitted. Maximum frame length is capped at 64 MiB.

> **Migration note:** releases of alostcp before this one used an unauthenticated AES-128-CTR stream and a different wire format. AEGIS-128L is **not wire-compatible** with those releases — upgrade both peers together.

---

## Benchmarks

All numbers measured on a single machine (**AMD Ryzen 7 5700X, Windows 11, Go 1.26.2**).

> **What the numbers mean:**
> - **Cipher benchmark** = pure in-memory seal/open speed. No network, no syscalls — just how fast the CPU can encrypt-and-authenticate a buffer.
> - **TCP ping-pong** = send one message, wait for one reply. Dominated by round-trip latency and syscall overhead; the cipher is a tiny fraction of the total.
> - **TCP streaming** = firehose mode. Batches many sends into fewer syscalls via `bufio.Writer`. This is where real-world throughput lives.

### 1. Cipher performance (in-memory, AEGIS-128L)

*"How fast can the CPU encrypt **and authenticate** a buffer?"*

| Payload | Seal MB/s | Open MB/s | allocs |
|---------|-----------|-----------|--------|
| 64 B   | 1,879  | 1,519  | 0 |
| 256 B  | 6,061  | 4,882  | 0 |
| 1 KB   | 12,051 | 10,683 | 0 |
| 4 KB   | 14,934 | 15,332 | 0 |
| 16 KB  | 17,759 | 16,765 | 0 |
| 64 KB  | 17,802 | 17,304 | 0 |

**Key insight:** AEGIS-128L scales to ~18 GB/s on bulk payloads (≥4 KB), well above an unauthenticated AES-128-CTR baseline on the same hardware (~11 GB/s) — *while also authenticating*. At small sizes the fixed per-message cost (key/nonce init + finalization) and the 16-byte tag dominate, which is inherent to authenticated encryption.

### 2. TCP throughput -- ping-pong (round-trip)

*"How many round-trips per second can I do?"* One send + one reply over loopback TCP; the connection/handshake are set up **before** the timer starts.

| Payload | ns/op | MB/s |
|---------|-------|------|
| 1 KB  | ~40,700 | 25 |
| 16 KB | ~48,000 | 340 |
| 64 KB | ~87,000 | 750 |

Round-trip latency is dominated by the kernel and syscalls; the cipher is a small fraction, so encrypted ping-pong tracks raw TCP closely.

### 3. TCP throughput -- streaming (true throughput)

*"How fast can I push data in one direction?"* Client sends continuously via `SendBuffered()` + `Flush()`; server receives with `RecvInto`.

| Payload | ns/op | MB/s |
|---------|-------|------|
| 1 KB  | ~464    | 2,205 |
| 4 KB  | ~1,582  | 2,589 |
| 16 KB | ~6,104  | 2,684 |
| 64 KB | ~24,891 | 2,633 |

The zero-copy receive path keeps bulk streaming at ~2.6 GB/s on loopback — at parity with the previous unauthenticated cipher, now with authentication included. Small messages carry the AEAD per-message overhead and are correspondingly slower.

*Reproduce with:* `go test -run '^$' -bench 'Benchmark(AEGIS|TCP)' ./core`

---

## Security notes

- **Authenticated:** AEGIS-128L provides confidentiality and integrity. Modified frames (ciphertext, tag, or length) are rejected, and the affected connection is poisoned.
- **Per-connection nonces:** each direction uses an independent counter nonce seeded from a handshake-derived IV, so nonces never repeat within a connection and never collide between directions.
- **Constant-time handshake check:** the password proof is compared in constant time.
- **Known limitation — no forward secrecy (yet):** the AEGIS key is derived solely from the password (`SHA256(password)`), so it is the same across connections. If the password is disclosed, previously captured traffic can be decrypted, and a weak password is brute-forceable offline from a captured handshake. An ephemeral key exchange (X25519) is the planned fix. Until then, use a strong, high-entropy password.

This library has not undergone an independent security audit. Review it before relying on it for high-stakes traffic.

---

## Roadmap

Planned / under consideration, roughly in priority order:

1. **Forward secrecy** — ephemeral X25519 key exchange in the handshake, authenticated by the password, for per-session keys.
2. **Portability fallback** — AES-NI detection plus a pure-Go / non-amd64 path so the library builds and runs on arm64 and CPUs without AES-NI.
3. **`net.Conn` adapter** — streaming `Read`/`Write` so alostcp drops into `io.Copy`, `net/http`, etc.
4. **Config struct** — tunable buffer sizes, max frame size, keepalive, and NoDelay.
5. **Hardening & quality** — configurable frame-size limits, fuzz tests on frame parsing, and official AEGIS test-vector coverage.

---

## Requirements

- Go 1.26+
- **amd64 with AES-NI** (the production cipher is AES-NI assembly; there is currently no non-amd64 / no-AES-NI fallback — see the roadmap)
- Windows or Linux
