# Building Quiver on Windows

This document covers everything needed to build and run Quiver on Windows.
Quiver is believed to be the **first pure-Swift QUIC/HTTP/3 library to run natively on Windows**.

---

## Prerequisites

### 1. Swift Toolchain

Download and install **Swift 6.1+** from [swift.org/install/windows](https://swift.org/install/windows/).

> **Note:** Swift 6.3.x has a known issue on Windows debug builds where
> `libswiftSwiftOnoneSupport.lib` and `libFoundationEssentials.lib` define
> duplicate symbols (`_insertionSort`). If you hit duplicate symbol errors,
> either use `-c release` or downgrade to Swift 6.2.x.

Verify your installation:

```powershell
swift --version
# Swift version 6.1.x (swift-6.1.x-RELEASE)
# Target: x86_64-unknown-windows-msvc
```

### 2. Visual Studio 2022 (Build Tools)

Required for the MSVC linker (`lld-link`) and Windows SDK headers.

Install **Visual Studio 2022** (Community or Build Tools) with:
- **Desktop development with C++** workload
- Windows 11 SDK (any recent version)

### 3. vcpkg (for `curl.lib`)

Foundation/FoundationNetworking on Windows autolinks `curl.lib`. You must provide it via vcpkg.

Quiver ships a `vcpkg.json` manifest. If you have vcpkg available (it is bundled with Visual Studio):

```powershell
# From the quiver directory:
vcpkg install --triplet x64-windows
```

This installs curl into `vcpkg_installed/` (already in `.gitignore`).

Then add the lib path to your environment before building:

```powershell
$env:LIB += ";$PWD\vcpkg_installed\x64-windows\lib"
$env:PATH += ";$PWD\vcpkg_installed\x64-windows\bin"
```

> **Tip:** Add these to your PowerShell profile or a project `.env` script so
> you don't need to repeat them each session.

### 4. Local dependency overrides

Quiver uses local path overrides for `swift-nio` and `swift-nio-ssl` that contain
Windows-specific fixes not yet merged upstream. Clone them alongside Quiver:

```powershell
# Required siblings (clone into the same parent folder as quiver/):
git clone https://github.com/hironichu/swift-nio      ../swift-nio
git clone https://github.com/hironichu/swift-nio-ssl   ../swift-nio-ssl
```

The `Package.swift` points to these via relative paths automatically when
`SWIFTCI_USE_LOCAL_DEPS=1` is set (see below).

---

## Environment Setup

Create a PowerShell session with the right environment before building.

### Developer Command Prompt

Open **x64 Native Tools Command Prompt for VS 2022**, then launch PowerShell
inside it, or run this from a regular PowerShell:

```powershell
# Load VS environment (adjust path to your VS installation):
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

### Required environment variables

```powershell
# Use local path overrides for swift-nio / swift-nio-ssl
$env:SWIFTCI_USE_LOCAL_DEPS = "1"

# curl.lib from vcpkg (run from quiver/ directory)
$env:LIB  += ";$PWD\vcpkg_installed\x64-windows\lib"
$env:PATH += ";$PWD\vcpkg_installed\x64-windows\bin"
```

---

## Building

```powershell
# Debug build (faster compile, more verbose)
swift build

# Release build (recommended for benchmarking or deployment)
swift build -c release

# Build a specific product
swift build --product HTTP3Demo
swift build --product HTTP3AuthDemo
```

---

## Running the Demo Server

Generate TLS certificates first (requires OpenSSL):

```powershell
cd certs
# See certs/README.md for generation instructions
```

Then start the server:

```powershell
.\.build\debug\HTTP3Demo.exe server `
    --cert ./certs/localhost.crt `
    --key  ./certs/localhost.key
```

And connect with the demo client:

```powershell
.\.build\debug\HTTP3Demo.exe client --ca-cert ./certs/localCA.crt
```

---

## Known Windows-Specific Fixes

The following platform-specific fixes are included in Quiver and its local
`swift-nio` fork. They are documented here for transparency and to help
upstream contributions.

### NIOPosix — `SocketChannel.swift`

**Problem:** `shouldCloseOnError` on Windows hits `default: return true` for
all Winsock errors, including `WSAECONNRESET` (10054). When a UDP client
disconnects, Windows delivers an ICMP "port unreachable" to the server socket
as `WSAECONNRESET` on the next `recvmsg`, which caused the datagram channel
to be closed.

**Fix:** Added a `case .winsock(WSAECONNRESET)` arm that returns `false`
(non-fatal), mirroring how `ECONNREFUSED` is treated on Linux.

### NIOPosix — `BSDSocketAPIWindows.swift`

**Problem:** `WSARecvMsg` and `WSASendMsg` threw on `WSAEWOULDBLOCK` instead
of returning `.wouldBlock(0)`, causing spurious errors on non-blocking socket
reads/writes.

**Fix:** Both functions now check for `WSAEWOULDBLOCK` and return `.wouldBlock(0)`.

### CNIOWindows — `shim.c`

**Problem:** `CNIOWindows_sendmmsg` was a stub that called `abort()`. NIO's
datagram channel uses `sendmmsg` for vector writes (multiple datagrams per
syscall). On Windows this path was hit immediately after the first QUIC
connection, crashing the process.

**Fix:** `CNIOWindows_sendmmsg` is now implemented as a loop over `WSASendMsg`
calls, emulating the Linux `sendmmsg` semantics (returns count of messages
sent; stops on first error).

### NIOUDPTransport — `NIOUDPTransport.swift`

**Problem:** `ChannelOptions.explicitCongestionNotification` (ECN) sets
`IP_RECVTOS` via setsockopt, which is not supported by Winsock on UDP sockets.
Setting it caused the channel bootstrap to fail with "Operation unsupported"
before `bind()` could complete.

**Fix:** ECN channel option is skipped with `#if !os(Windows)`.

### Quiver — `QUICSocketConfiguration`

`enableECN` and `enableDF` (Don't Fragment bit) default to `true` on all
platforms but have no effect on Windows (ECN not supported by Winsock;
DF-bit control not exposed). Platform socket options gracefully degrade:
`isDFSupported` and `isECNSupported` return `false` on Windows, so no
options are applied and the socket operates normally.

---

## Troubleshooting

### `lld-link: error: could not open 'curl.lib'`

`curl.lib` is autolinked by `FoundationNetworking`. Set `$env:LIB` to
include the vcpkg lib directory as shown above.

### Duplicate symbol `_insertionSort` linker error

This is a Swift 6.3.x toolchain bug on Windows debug builds. Workarounds:
- Build with `-c release`: `swift build -c release`
- Downgrade to Swift 6.2.x

### `Failed to bind: Operation unsupported`

ECN socket option was being applied on Windows. Fixed in the current codebase
via `#if !os(Windows)`. If you see this on an older checkout, rebuild after
pulling the fix.

### `Assertion failed: !"sendmmsg not implemented"`

The `CNIOWindows_sendmmsg` stub was hit. Fixed in the local `swift-nio` fork
(`Sources/CNIOWindows/shim.c`). Ensure you are using the local fork.

### `NIOUDPTransport channel error: An existing connection was forcibly closed`

`WSAECONNRESET` from the OS after a client closes its connection. This is
expected on Windows UDP sockets — it is now treated as non-fatal and suppressed
in debug output. The server channel stays open.
