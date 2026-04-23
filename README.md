# alostcp

Zero-friction, end-to-end encrypted TCP for Go. One password, one import, full protection.

```bash
go get github.com/guno1928/alostcp
```

```go
import "github.com/guno1928/alostcp/core"
```

## Why alostcp?

- **Transparent encryption** -- Every packet is auto-encrypted with a per-connection AES-128-CTR stream. No manual crypto calls.
- **Anti-MITM handshake** -- On connect, both sides prove they know the shared password before any data flows.
- **Zero-allocation hot path** -- Pooled buffers, `unsafe` string conversions, and a custom AES-NI assembly cipher that outperforms Go's stdlib.
- **Cross-platform** -- Windows and Linux on amd64.

---

## 6 Usage Examples

### 1. Client -- send a string

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

### 2. Server -- echo a string

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

### 3. Binary send and receive

```go
conn, _ := core.Connect("127.0.0.1", 9000, "secret")
defer conn.Close()

payload := []byte{0x01, 0x02, 0x03}
conn.Send(payload)

response, _ := conn.Recv()
```

### 4. Wrong password is rejected at handshake

```go
// Server
ln, _ := core.Listen(9000, "correct-password")
conn, err := ln.Accept()
// err == nil only if client proved it knows "correct-password"

// Client with wrong password
conn, err := core.Connect("127.0.0.1", 9000, "wrong-password")
// err != nil -- handshake fails, MITM or wrong key detected
```

### 5. Concurrent echo server

```go
ln, _ := core.Listen(9000, "secret")
defer ln.Close()

for {
    conn, _ := ln.Accept()
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

### 6. High-throughput streaming

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

---

## How It Works

1. **Dial / Accept** -- Raw TCP socket is established.
2. **Anti-MITM Handshake** -- Server sends a one-time password encrypted with the shared secret. Client decrypts it, computes `SHA256(OTP || password)`, and sends it back. Server verifies with constant-time comparison. If either side has the wrong password, the connection is dropped immediately.
3. **Encrypted Traffic** -- After handshake, every `Send` advances the AES-128-CTR stream, encrypts the payload, and transmits `[length][ciphertext]`. Every `Recv` reads the frame and decrypts using the matching stream. Each direction uses an independent CTR stream so counters never collide.

### Cipher: AES-128-CTR-ASM-8B

ALOSTCP uses a **custom AES-128-CTR implementation** built on Go's internal AES-NI assembly (`ctrBlocks{1,2,4,8}Asm`) with a hand-rolled key schedule. We evaluated **25 cipher candidates** (AES variants, ChaCha20, Salsa20, SPECK, SIMON, LEA, Threefish, Camellia, SM4, SEED, ARIA, RC4, HC-128) and the custom 8-block parallel AES-128 won on both throughput and latency.

The custom cipher keeps the expanded key hot in cache, pipelines 8 counter blocks per assembly call, and eliminates the per-call overhead that limits Go's stdlib at small packet sizes.

---

## Benchmarks

All numbers measured on a single machine (**AMD Ryzen 7 5700X, Windows 11, Go 1.26.2**).

> **What the numbers mean:**
> - **Cipher benchmark** = pure in-memory encryption speed. No network, no syscalls, no kernel — just how fast the CPU can XOR plaintext with the keystream.
> - **TCP ping-pong** = send one packet, wait for one reply. Dominated by round-trip latency and syscall overhead. The cipher is only a tiny fraction of the total time here.
> - **TCP streaming** = firehose mode. Batches many sends into fewer syscalls. This is where real-world throughput lives.

---

### 1. Cipher Performance (In-Memory Encryption Only)

This answers: *"How fast can the CPU encrypt a buffer?"*

| Payload | Stdlib MB/s | Custom MB/s | Gain | Stdlib PPS | Custom PPS |
|---------|-------------|-------------|------|------------|------------|
| 64 B   | 3,704  | 5,715  | **+54%** | 57.9 Mpps | 89.3 Mpps |
| 256 B  | 7,720  | 10,332 | **+34%** | 30.2 Mpps | 40.4 Mpps |
| 512 B  | 8,774  | 10,679 | **+22%** | 17.1 Mpps | 20.9 Mpps |
| 1 KB   | 9,902  | 11,079 | **+12%** | 9.7 Mpps  | 10.8 Mpps |
| 4 KB   | 10,298 | 11,092 | **+8%**  | 2.5 Mpps  | 2.7 Mpps  |
| 16 KB  | 10,746 | 10,912 | **+2%**  | 656 Kpps  | 666 Kpps  |
| 64 KB  | 10,464 | 11,078 | **+6%**  | 160 Kpps  | 169 Kpps  |

*All cipher paths run at **0 B/op, 0 allocs/op**.*

**Key insight:** The biggest wins are at small packet sizes (64 B–1 KB) where the 8-block parallel assembly reduces loop overhead. At large sizes both implementations approach the AES-NI hardware ceiling (~11 GB/s).

---

### 2. TCP Throughput -- Ping-Pong (Round-Trip Latency)

This answers: *"How many round-trips per second can I do?"*

One send + one reply over loopback TCP. The connection and handshake are set up **before** the timer starts — only the send→reply loop is measured. This is dominated by RTT, kernel scheduling, and syscall overhead. The cipher is a tiny fraction of the total time.

| Payload | Library | ns/op | MB/s | PPS | Allocs |
|---------|---------|-------|------|-----|--------|
| 1 KB | `net/tcp` (raw) | 28,593 | 35.8 | **35.0 K** | 0 |
| 1 KB | `net/tcp` + framing | 64,329 | 15.9 | **15.5 K** | 1 |
| 1 KB | `alostcp/core` | 40,892 | 25.0 | **24.5 K** | 4 |
| 64 KB | `net/tcp` (raw) | 56,484 | 1,160 | **17.7 K** | 0 |
| 64 KB | `net/tcp` + framing | 91,501 | 716 | **10.9 K** | 1 |
| 64 KB | `alostcp/core` | 111,907 | 586 | **8.9 K** | 4 |

*ALOSTCP adds encryption + framing overhead on top of raw TCP. For 1 KB the overhead is ~12 us (43% of raw TCP). For 64 KB the overhead is ~55 us (97% of raw TCP time). This is expected — you cannot encrypt faster than doing nothing.*

---

### 3. TCP Throughput -- Streaming (True Throughput)

This answers: *"How fast can I push data in one direction?"*

Client sends continuously; server receives and discards. ALOSTCP uses `SendBuffered()` + `Flush()` to batch writes via `bufio.Writer`. This is the number that matters for real workloads (file transfer, video streaming, telemetry firehoses).

| Payload | Library | ns/op | MB/s | PPS | Allocs |
|---------|---------|-------|------|-----|--------|
| 1 KB | `net/tcp` (raw) | 14,766 | 69.4 | **67.7 K** | 0 |
| 1 KB | `net/tcp` + framing | 27,606 | 37.1 | **36.2 K** | 2 |
| 1 KB | `alostcp/core` | 523 | 1,957 | **1,911 K** | 2 |
| 64 KB | `net/tcp` (raw) | 26,498 | 2,473 | **37.7 K** | 0 |
| 64 KB | `net/tcp` + framing | 44,262 | 1,481 | **22.6 K** | 2 |
| 64 KB | `alostcp/core` | 29,790 | 2,200 | **33.6 K** | 2 |

**Key results:**
- **1 KB streaming: 28.2x faster than raw TCP** -- `bufio.Writer` batches ~500 small messages into a single 256 KB TCP segment. Raw TCP pays a syscall on every 1 KB write.
- **1 KB streaming: 52.7x faster than framed raw TCP** -- Adding a 4-byte length header to raw TCP (same wire format as ALOSTCP) doubles the syscall count and eliminates kernel batching.
- **64 KB streaming: 89% of raw TCP** -- At 64 KB, raw TCP already saturates the kernel pipe. ALOSTCP adds ~3 us of AES-NI encryption overhead. This is the physical limit of encrypted TCP.

---

## Requirements

- Go 1.26+
- amd64 architecture (AES-NI required for the fast path; software fallback exists but is slower)
- Windows or Linux
