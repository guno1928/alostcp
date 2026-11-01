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

- **Authenticated encryption** -- Every message is sealed with **AEGIS-128L**, a modern AEAD cipher. You get confidentiality *and* integrity: any tampering with the ciphertext, the auth tag, or the length header is detected and rejected.
- **Password-authenticated key exchange (CPace)** -- The handshake is [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) over ristretto255, a balanced PAKE built for one shared password. Nothing on the wire, not even what a fake server collects from a real client, can be tested against password guesses offline: every attempt is one online guess.
- **Mutually authenticated, replay-proof handshake** -- Both sides contribute fresh ephemeral keys and each confirms the shared key before any data flows. A recorded handshake cannot be replayed, and a man-in-the-middle without the password cannot complete one with either side.
- **Forward secrecy** -- Every connection gets its own keys, one per direction, derived from ephemeral secrets. Learning the password later does not decrypt previously recorded traffic.
- **Drops into the standard library** -- `*Conn` is a `net.Conn` (`Read`/`Write`), `Listener.NetListener()` is a `net.Listener`, and `DialContextFunc` plugs into `http.Transport`, so `io.Copy` and `net/http` work over alostcp unchanged.
- **Tunable** -- An optional `Config` sets buffer sizes, the message size limit, handshake timeout and concurrency, TCP keepalive, and an accept filter for rate limiting.
- **Fast bulk throughput** -- A hand-written AEGIS-128L AES-NI assembly cipher, validated byte-for-byte against the reference implementation, sealing straight into the send buffer and decrypting straight out of the receive buffer, with no per-message heap allocations on the `Send`/`SendBuffered`/`RecvInto` path (0 allocs/op in the benchmarks).
- **Timeouts built in** -- Context- and deadline-aware dialing, per-operation read/write deadlines, and a read timeout between messages never breaks the connection.
- **Tiny surface** -- Connect, Listen, Send, Recv. No TLS config, no certificates, no PKI.
- **Checked against the standards** -- The AEGIS-128L cipher passes the RFC 10032 test vectors and the CPace code passes the draft's ristretto255 test vectors; the frame parser and handshakes are fuzzed.

---

## Quick start

**Server**

```go
package main

import (
    "errors"
    "log"
    "net"

    "github.com/guno1928/alostcp/core"
)

func main() {
    ln, err := core.Listen(9000, "shared-password")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if errors.Is(err, net.ErrClosed) {
            return
        }
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go func(c *core.Conn) {
            defer c.Close()
            msg, err := c.RecvString()
            if err != nil {
                return
            }
            log.Println("received:", msg)
        }(conn)
    }
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

`Accept` only ever returns connections that completed the password handshake. Clients that send garbage, use the wrong password, or connect and go silent are dropped in the background and never surface as `Accept` errors, so a port scan cannot crash or stall your accept loop.

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
conn, err := core.Connect("127.0.0.1", 9000, "wrong-password")
// errors.Is(err, core.ErrHandshake) == true
```

The server closes the connection without sending its key confirmation. What a wrong-password client did receive (the server's CPace public value) cannot be used to test further password guesses.

### Concurrent echo server

```go
ln, err := core.Listen(9000, "secret")
if err != nil {
    log.Fatal(err)
}
defer ln.Close()

for {
    conn, err := ln.Accept()
    if errors.Is(err, net.ErrClosed) {
        return
    }
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
            if err := c.SendString("echo: " + msg); err != nil {
                return
            }
        }
    }(conn)
}
```

Handshakes run concurrently in the background (up to 1,024 at a time), so a slow or idle client never delays the next legitimate one.

It is safe to call `Send`/`SendBuffered`/`Flush` from multiple goroutines and `Recv`/`RecvInto` from another; writes and reads are independently serialized.

### High-throughput streaming

```go
conn, _ := core.Connect("127.0.0.1", 9000, "secret")
defer conn.Close()

payload := make([]byte, 1024)
for i := 0; i < 10000; i++ {
    conn.SendBuffered(payload)
}
conn.Flush()
```

`Close` also flushes anything still queued by `SendBuffered`.

### Reusing a buffer on receive

`RecvInto` decrypts directly into a caller-supplied buffer (no per-message allocation):

```go
buf := make([]byte, 64*1024)
for {
    n, err := conn.RecvInto(buf)
    if errors.Is(err, io.ErrShortBuffer) {
        buf = make([]byte, n)
        continue
    }
    if err != nil {
        break
    }
    process(buf[:n])
}
```

If a message is larger than `buf`, `RecvInto` consumes nothing, returns the message size as `n`, and returns an error wrapping `io.ErrShortBuffer`. The connection stays usable, so retry with a bigger buffer. If a message fails authentication, the part of `buf` it was decrypted into is zeroed before `RecvInto` returns.

### Timeouts and deadlines

```go
// Bound the dial + handshake with a duration...
conn, err := core.ConnectTimeout("127.0.0.1", 9000, "secret", 5*time.Second)

// ...or with a context. Both a deadline and a plain cancel are honored
// during the TCP connect and the handshake.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
conn, err = core.ConnectContext(ctx, "127.0.0.1", 9000, "secret")

// Per-operation deadlines (passthrough to the TCP socket):
conn.SetReadDeadline(time.Now().Add(2 * time.Second))
conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
conn.SetDeadline(time.Now().Add(2 * time.Second))

// Bound how long Accept waits for a new connection:
ln.SetDeadline(time.Now().Add(time.Second))

// Bound how long an unauthenticated client may take to finish the handshake (default 5s):
ln.SetHandshakeTimeout(2 * time.Second)
```

What an expired deadline does to the connection:

| Situation | Result |
|---|---|
| Read deadline expires while waiting for a message, or partway through a message of up to 256 KiB | `Recv` returns an error wrapping `os.ErrDeadlineExceeded`. Nothing is consumed and **the connection stays usable**: clear or extend the deadline and call `Recv` again. |
| Read deadline expires partway through a message larger than 256 KiB (the default `ReadBufferSize`) | The connection is *poisoned* (see below). |
| Write deadline expires during `Send`/`SendBuffered`/`Flush` | The connection is *poisoned*. |
| Write deadline had already passed when `Write` was called | `Write` returns `0` and a timeout error without touching the socket. **The connection stays usable.** |
| Write deadline expires partway through a `Write` (every OS except Windows; tested on Linux) | `Write` returns the bytes it accepted and a timeout error. Accepted bytes that are not on the wire yet stay buffered and are sent before anything else. **The connection stays usable**: write the rest of the data again. |
| Write deadline expires partway through a `Write` (Windows) | The connection is *poisoned*. Windows does not report how many bytes a timed-out send really transmitted (it reports none even when all of it went out), so the stream cannot be resumed safely. |

Timeout errors satisfy `net.Error` with `Timeout() == true`, including the poisoning ones.

`Send` blocks while the peer is not reading (TCP back-pressure) and holds the send lock while it does, so other senders on the same connection wait too. Set a write deadline if a slow peer must not stall you.

`Connect` without a timeout or context blocks until the server answers; use `ConnectTimeout` or `ConnectContext` to bound it.

### Closing

`Close` flushes queued messages and sends an authenticated *close notification* (waiting at most one second for the socket to accept it). The peer's next `Recv` then returns `io.EOF`. If the connection ends without one, for example because the process died or an attacker cut the stream, the peer instead gets an error wrapping both `core.ErrConnBroken` and `io.ErrUnexpectedEOF`, so truncation is always detectable. If another goroutine is in the middle of a `Send` when `Close` is called, `Close` skips the notification and just closes the socket. As with any TCP socket, closing while the peer's data is still unread can make the operating system reset the connection, in which case the peer sees `ErrConnBroken` instead of `io.EOF`; read what the peer sent before closing if a clean `io.EOF` matters.

After `Close`, every operation on the connection returns `core.ErrConnClosed`, including a `Recv` that was blocked at the time. Calling `Close` again, or on a poisoned connection, returns `nil`.

### Custom accept loops

`AcceptRaw` returns the raw TCP connection and `Handshake` runs the server handshake on it (honoring the handshake timeout; it replaces any deadline already set on the connection and clears it on success). `Handshake` closes the connection if the handshake fails. Use them if you need to inspect or filter connections before authenticating them. Do not mix them with `Accept` on the same listener.

```go
raw, err := ln.AcceptRaw()
if err != nil {
    return
}
go func() {
    conn, err := ln.Handshake(raw)
    if err != nil {
        return
    }
    defer conn.Close()
    // ...
}()
```

### Configuration

`ListenConfig` and `DialConfig` take an optional `*Config`. A nil config, or any field left at its zero value, means the default, so `Listen`/`Connect` behave exactly like `ListenConfig`/`DialConfig` with `nil`.

```go
cfg := &core.Config{
    MaxMessageSize:       1 << 20,
    HandshakeTimeout:     2 * time.Second,
    MaxPendingHandshakes: 256,
    KeepAlive:            &net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second},
    AcceptFilter: func(remote net.Addr) bool {
        return limiter.Allow(remote.(*net.TCPAddr).IP.String())
    },
}
ln, err := core.ListenConfig("", 9000, "secret", cfg)

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
conn, err := core.DialConfig(ctx, "127.0.0.1", 9000, "secret", &core.Config{MaxMessageSize: 1 << 20})
```

| Field | Default | Allowed | Applies to |
|---|---|---|---|
| `ReadBufferSize` | 256 KiB | 64 KiB - 64 MiB | both sides. Messages up to this size survive a read timeout. |
| `WriteBufferSize` | 256 KiB | 64 KiB - 64 MiB | both sides |
| `MaxMessageSize` | `MaxMessageSize` (64 MiB - 16) | 1 KiB - `MaxMessageSize` | both sides. The largest message this side accepts **and** sends. Each side announces it in the handshake; a sender is limited to the smaller of its own and its peer's value. |
| `HandshakeTimeout` | 5 s | > 0 | listener; `SetHandshakeTimeout` still changes it later. The dial side is bounded by its context. |
| `MaxPendingHandshakes` | 1,024 | 1 - 65,536 | listener |
| `KeepAlive` | nil (Go's default: on, 15 s) | non-negative fields | both sides. `&net.KeepAliveConfig{}` turns keepalive off. |
| `AcceptFilter` | nil (accept all) | | listener `Accept` only. Called on the accept goroutine with the peer's address before anything is read; returning `false` closes the socket. Keep it fast. Not used by `AcceptRaw`. |

An out-of-range value makes `ListenConfig`/`DialConfig` return an error wrapping `ErrInvalidConfig`. The config is copied, so changing it afterwards has no effect.

### Using alostcp as a net.Conn

`*Conn` implements `net.Conn`. `Write` splits data into frames of up to 64 KiB, and `Read` returns decrypted bytes as a plain stream, so the standard library works on top of it:

```go
// io.Copy
_, err := io.Copy(conn, file)

// An HTTP server...
srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
go srv.Serve(ln.NetListener())

// ...and a client that dials through alostcp.
client := &http.Client{Transport: &http.Transport{
    DialContext: core.DialContextFunc("secret", nil),
}}
resp, err := client.Get("http://127.0.0.1:9000/hello")
```

Each `Send` on one side arrives as bytes for `Read` on the other, and each `Write` arrives as one or more messages for `Recv`. On a single connection, pick one style per direction. If you do switch, `Recv`/`RecvInto` first return whatever is left of a message that `Read` only partly consumed. `DialContextFunc` accepts the networks `tcp`, `tcp4` and `tcp6` and always dials with `tcp`.

---

## API reference

### Dialing

```go
func Connect(ip string, port int, password string) (*Conn, error)
func ConnectContext(ctx context.Context, ip string, port int, password string) (*Conn, error)
func ConnectTimeout(ip string, port int, password string, timeout time.Duration) (*Conn, error)
```

```go
func DialConfig(ctx context.Context, ip string, port int, password string, cfg *Config) (*Conn, error)
func DialContextFunc(password string, cfg *Config) func(ctx context.Context, network, addr string) (net.Conn, error)
```

`ip` may be an IPv4 or IPv6 literal or a host name.

### Listening

```go
func Listen(port int, password string) (*Listener, error)                  // all interfaces
func ListenHost(host string, port int, password string) (*Listener, error) // e.g. "127.0.0.1" or "::1"
func ListenConfig(host string, port int, password string, cfg *Config) (*Listener, error)
func (ln *Listener) NetListener() net.Listener          // Accept returns *Conn as net.Conn

func (ln *Listener) Accept() (*Conn, error)              // authenticated connections only
func (ln *Listener) SetDeadline(t time.Time) error       // bounds Accept; zero value clears
func (ln *Listener) SetHandshakeTimeout(d time.Duration) // default 5s; d <= 0 restores the default
func (ln *Listener) AcceptRaw() (*net.TCPConn, error)
func (ln *Listener) Handshake(conn *net.TCPConn) (*Conn, error)
func (ln *Listener) Close() error                        // also aborts in-flight handshakes
func (ln *Listener) Addr() net.Addr
```

After `Close`, `Accept` returns an error for which `errors.Is(err, net.ErrClosed)` is true. When the `SetDeadline` deadline passes, it returns an error for which `errors.Is(err, os.ErrDeadlineExceeded)` is true.

### Connection

```go
const MaxMessageSize = 64<<20 - 16

// Sending
func (c *Conn) Send(data []byte) error          // seal + write + flush
func (c *Conn) SendBuffered(data []byte) error  // seal + buffer (no flush)
func (c *Conn) Flush() error                     // flush buffered writes
func (c *Conn) SendString(s string) error

// Receiving
func (c *Conn) Recv() ([]byte, error)            // freshly allocated payload; io.EOF after the peer closes
func (c *Conn) RecvInto(buf []byte) (int, error) // into buf; io.ErrShortBuffer if too small
func (c *Conn) RecvString() (string, error)

// Streaming (net.Conn)
func (c *Conn) Read(p []byte) (int, error)
func (c *Conn) Write(p []byte) (int, error)

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

| Error | Meaning |
|---|---|
| `ErrHandshake` | The handshake failed: wrong password, a non-alostcp peer, a tampered or replayed handshake, a timeout, or cancellation. Wrapped errors keep the cause, e.g. `errors.Is(err, context.Canceled)`. |
| `ErrEmptyPassword` | `Listen`/`Connect` was given an empty password. |
| `ErrInvalidConfig` | A `Config` field is out of range (see [Configuration](#configuration)). |
| `ErrUnsupportedCPU` | The CPU has no hardware AES (see [Requirements](#requirements)). |
| `ErrMessageTooLarge` | A payload exceeds the connection's message limit (the smaller of both sides' `MaxMessageSize`). Nothing is sent and the connection stays usable. |
| `ErrConnClosed` | The connection was closed with `Close`. |
| `ErrConnBroken` | The connection is poisoned. |

A connection is *poisoned* when a message fails authentication, a frame header is invalid, the stream ends without a close notification, or I/O fails partway through a frame (except for the recoverable read timeouts above). It is closed, the error that poisoned it wraps `ErrConnBroken` together with its cause, and every later call returns that same error. Test with `errors.Is(err, core.ErrConnBroken)`.

---

## How it works

1. **Password key** -- The password is stretched once per process with PBKDF2-HMAC-SHA256 (600,000 iterations, about 85 ms on a desktop CPU; `Listen` pays it up front and clients cache it per password).
2. **Handshake (CPace)** -- Both sides map the password key, a fixed channel identifier and a 16-byte session id chosen by the client onto a ristretto255 group element `g` (hash-to-group with SHA-512, as specified in draft-irtf-cfrg-cpace-21). Each side picks a fresh random scalar `y` and sends `y·g`. Both compute `K = y·(peer value)`, reject the identity element, and hash `K`, the session id and both messages into the CPace session key. HKDF-SHA256 over that key, salted with a hash of both hellos, yields a client proof, a server proof, and one AEGIS-128L key per direction. Each hello also carries the sender's message size limit, which is part of the hashed transcript.
3. **Proofs** -- The client sends its proof first. The server checks it in constant time and, only if it is correct, sends its own proof, which the client checks in constant time. Because every proof depends on both fresh ephemeral secrets, nothing from an earlier handshake verifies in a new one, and a client cannot be tricked into reusing old keys. Someone without the password who plays either side can try exactly one password guess per handshake, and learns nothing that would let them test more guesses offline.
4. **Encrypted traffic** -- Every `Send` seals the payload with AEGIS-128L and transmits `[4-byte header][ciphertext ‖ 16-byte tag]`. The header is bound into the tag as **associated data**. Each direction uses its own key and a 128-bit message counter as the nonce (implicit, never sent), so a nonce never repeats under a key.
5. **Close** -- `Close` sends an authenticated close notification so the receiver can tell a clean end of stream from a truncated one.

### Cipher: AEGIS-128L (AEAD)

alostcp uses **AEGIS-128L**, a high-performance authenticated cipher built on the AES round function. Unlike a raw stream cipher, AEGIS produces a 128-bit authentication tag per message: tampering is cryptographically detected rather than silently decrypted into garbage.

On amd64 the cipher is a **hand-written AES-NI assembly implementation** (`aegis128l_amd64.s`) that keeps all eight 128-bit state words in XMM registers across the whole message, handling init, associated-data absorption, encryption, and finalization in a single call. Both it and the library engine pass all nine AEGIS-128L test vectors of [RFC 10032](https://datatracker.ietf.org/doc/rfc10032/) (five that must verify and four that must fail). The assembly is also differentially tested against the reference implementation ([`github.com/ericlagergren/aegis`](https://github.com/ericlagergren/aegis)) in both directions (seal and open, including in-place open) for message sizes 0–65,536 bytes with associated data of 0–64 bytes, plus 2,000 randomized cases per run. On arm64 alostcp uses that reference implementation, which has its own hardware-AES assembly.

---

## Wire format

**Handshake** (fixed sizes, no length fields)

```
client -> server   hello      [ "ALTC" ][ version = 3 ][ 4-byte message limit ][ 16-byte session id ][ 32-byte CPace value ]   57 bytes
server -> client   hello      [ "ALTC" ][ version = 3 ][ 4-byte message limit ][ 32-byte CPace value ]                          41 bytes
client -> server   finished   [ 32-byte client proof ]
server -> client   finished   [ 32-byte server proof ]
```

The message limit is big-endian and must be between 1 KiB and `MaxMessageSize`; a hello outside that range, with another version, or with an invalid or identity CPace value is rejected before the server sends anything.

**Data frame** (post-handshake)

```
[ 4 bytes ] big-endian header: bit 31 = close notification, bits 0-30 = L = len(plaintext) + 16
[ L bytes ] ciphertext ‖ 16-byte AEGIS tag   (the 4 header bytes are the associated data)
```

A close notification is a frame with bit 31 set and an empty plaintext. `L` is capped at 64 MiB, or lower if the receiver announced a smaller message limit.

> **Migration note:** this is protocol version 3 (CPace). It is **not wire-compatible** with version 2 (the X25519 handshake) or any earlier release; a v2 peer fails with `ErrHandshake`. Upgrade both peers together.

---

## Benchmarks

Measured on one desktop (**AMD Ryzen 7 5700X, Windows 11, Go 1.27.3**) as medians of 8 runs, interleaved with the previous (v2) release so both saw the same machine state. Against v2 the data path is unchanged within noise (geomean +0.8%, no benchmark significantly different) and still allocation-free. Loopback TCP on a desktop is noisy: the TCP numbers vary by ±10-90% between runs and by more between days.

*Reproduce with:* `go test -run '^$' -bench 'Benchmark(AEGIS128LAsm|TCP|Handshake)' -benchmem ./core`

### 1. Cipher performance (in-memory, AEGIS-128L assembly)

| Payload | Seal | Open | allocs |
|---------|------|------|--------|
| 64 B   | 1.6 GiB/s  | 1.3 GiB/s  | 0 |
| 1 KB   | 10.4 GiB/s | 8.7 GiB/s  | 0 |
| 4 KB   | 13.8 GiB/s | 13.5 GiB/s | 0 |
| 16 KB  | 15.5 GiB/s | 15.1 GiB/s | 0 |
| 64 KB  | 15.9 GiB/s | 14.7 GiB/s | 0 |

### 2. TCP ping-pong (one send + one reply, loopback)

| Payload | Round trip | allocs |
|---------|------------|--------|
| 64 B  | ~49 µs  | 0 |
| 1 KB  | ~50 µs  | 0 |
| 16 KB | ~62 µs  | 0 |
| 64 KB | ~110 µs | 0 |

Round-trip latency is dominated by the kernel and syscalls; the cipher is a small fraction.

### 3. TCP streaming (`SendBuffered` + `Flush` -> `RecvInto`, loopback)

| Payload | Throughput | allocs |
|---------|------------|--------|
| 64 B  | ~290 MiB/s | 0 |
| 256 B | ~850 MiB/s | 0 |
| 1 KB  | ~1.4 GiB/s | 0 |
| 4 KB  | ~1.7 GiB/s | 0 |
| 16 KB | ~1.7 GiB/s | 0 |
| 64 KB | ~1.8 GiB/s | 0 |

Streaming is bound by socket syscalls (about three quarters of the CPU profile), not by the cipher.

### 4. net.Conn streaming (`Write` -> `Read`, loopback)

| Write size | Throughput | allocs |
|---------|------------|--------|
| 64 B  | ~2.9 MiB/s | 0 |
| 1 KB  | ~45 MiB/s  | 0 |
| 4 KB  | ~170 MiB/s | 0 |
| 16 KB | ~600 MiB/s | 0 |
| 64 KB | ~1.3 GiB/s | 0 |

Like any `net.Conn`, every `Write` is sent immediately (one syscall, about 20 µs here), so many small writes are slow. Batch them with `bufio.Writer`, or use `SendBuffered` + `Flush`.

### 5. Connection setup (TCP connect + CPace handshake + close, loopback)

About **850 µs** per connection (v2's X25519 handshake: about 750 µs in the same runs), measured with the password key already cached. The first connection with a new password also pays the one-time PBKDF2 cost (about 85 ms).

---

## Security notes

- **Authenticated:** AEGIS-128L provides confidentiality and integrity. Modified frames (ciphertext, tag, header, or close flag) are rejected, and the affected connection is poisoned.
- **Replay-proof, mutually authenticated handshake:** both sides' proofs depend on fresh ephemeral keys from both sides, so recorded handshakes and frames cannot be replayed into new sessions, reflected back, or spliced between connections.
- **Forward secrecy:** per-connection keys come from ephemeral CPace secrets. Disclosing the password does not reveal previously recorded traffic.
- **Per-direction keys and nonces:** each direction has its own key and counter nonce, and a nonce is only ever used for one frame, including after a recovered write timeout (frames are kept and sent, never re-encrypted).
- **Password guessing:** CPace is a password-authenticated key exchange, so there is no offline attack: not for someone who records traffic, not for a client that connects without the password, and not for an attacker who impersonates the server to a real client (for example via DNS or ARP spoofing). Each of them gets exactly one password guess per handshake, checked online. Put rate limiting in front of servers that untrusted networks can reach; `Config.AcceptFilter` is the place to plug in a per-IP limiter. A short or common password can still be found by enough online guesses, so **use a long, random password**.
- **Protocol hellos:** the version, the message limit and the session id are covered by the key confirmation, so changing any of them in transit makes the handshake fail on both sides. Invalid and identity CPace values are rejected, as the CPace draft requires.
- **Constant-time checks:** handshake proofs and message tags are compared in constant time.
- **No unverified plaintext:** a message that fails authentication is never returned, and `RecvInto` zeroes the bytes it decrypted.
- **Resource limits:** handshakes are bounded by a timeout (default 5 s) and run at most 1,024 at a time (both configurable). A frame header alone cannot make the receiver allocate the full message: messages up to `ReadBufferSize` (default 256 KiB) are only allocated once all their bytes have arrived, and larger ones grow with the data, staying within twice `ReadBufferSize` or roughly twice the bytes received so far. This also holds for `Read`.
- **Tested:** RFC 10032 vectors for the cipher, CPace draft-21 ristretto255 vectors for the handshake math, mutation checks showing the security tests fail when a control is removed, and native Go fuzzing of frame parsing, both handshake roles and the two cipher engines against each other.

This library has not undergone an independent security audit. Review it before relying on it for high-stakes traffic.

---

## Roadmap

Done in this release:

- **`net.Conn` adapter** -- `Read`/`Write`, `NetListener` and `DialContextFunc`.
- **Config struct** -- buffer sizes, message limit, handshake timeout and concurrency, keepalive, accept filter.
- **PAKE handshake** -- CPace (protocol v3).
- **Hardening & quality** -- RFC 10032 and CPace test vectors, fuzz tests.

Possible next steps (not started): automatic rekeying for very long-lived connections, an exporter for channel binding, and an AEGIS assembly implementation for arm64.

---

## Requirements

- Go 1.26+ (developed and tested with Go 1.27.3; the module pins `toolchain go1.27.3`)
- Dependencies: `golang.org/x/sys` v0.49.0, `github.com/gtank/ristretto255` v0.2.0 (with `filippo.io/edwards25519` v1.2.0) for CPace, `github.com/ericlagergren/aegis` (latest commit, used for arm64 and as the test reference), and `golang.org/x/net` v0.62.0 for the `net.Conn` conformance tests only
- A CPU with hardware AES: **amd64 with AES-NI**, or **arm64 reporting the AES extension** (always assumed on macOS). On anything else `Listen` and `Connect` return `ErrUnsupportedCPU` rather than fall back to a table-based software AES that could leak timing.
- Builds on Windows, Linux, macOS, and FreeBSD for amd64 and arm64. The test suite is run on Windows/amd64 and Linux/amd64. `x/net/nettest`'s `net.Conn` conformance suite passes 11/11 on Linux; on Windows it passes 9/11, because `FutureTimeout` and `ConcurrentMethods` require resuming after a mid-write timeout, which Windows cannot support safely (see the timeout table). `TCP_NODELAY` is set on every connection; on Linux `TCP_QUICKACK` is also requested at connect time (the kernel may leave quick-ack mode again later; it is a hint, not a setting).
