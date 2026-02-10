// =============================================================================
// Quiver Benchmark Client
// =============================================================================
//
// High-throughput benchmark client exercising all protocol layers:
//   Phase 1: QUIC raw stream throughput (bulk unidirectional + bidirectional)
//   Phase 2: HTTP/3 variable payloads (HTML, big headers, large body, echo)
//   Phase 3: WebTransport stream reliability (bidi + uni integrity checks)
//   Phase 4: WebTransport datagram throughput (blast + loss measurement)
//
// Usage:
//   swift run BenchmarkClient [cert.pem key.pem]
//
// If no arguments, runs in development mode (self-signed TLS).
// =============================================================================

import Foundation
import Logging
import QUIC
import QUICCore
import QUICCrypto
import QUICTransport
import NIOUDPTransport
import HTTP3
import QPACK

// =============================================================================
// MARK: - Configuration (edit these directly)
// =============================================================================

let benchHost = "127.0.0.1"

/// Port for HTTP/3 + WebTransport (Phases 2, 3, 4)
let h3Port: UInt16 = 4500

/// Port for raw QUIC stream echo (Phase 1)
let quicPort: UInt16 = 4501

let h3ALPN = "h3"
let quicBenchALPN = "quic-bench"

/// QUIC phase config
let quicBulkStreamCount = 8
let quicBulkBytesPerStream = 4 * 1024 * 1024       // 4 MB per stream
let quicBidiBytesPerStream = 1 * 1024 * 1024        // 1 MB per bidi stream
let quicBidiStreamCount = 4
let quicChunkSize = 32 * 1024                        // 32 KB write chunks

/// HTTP/3 phase config
let h3Iterations = 10                                // repeat each endpoint N times
let h3EchoBodySize = 256 * 1024                      // 256 KB POST body
let h3UploadBodySize = 1 * 1024 * 1024               // 1 MB upload to /bench/sink

/// WebTransport stream reliability config
let wtBidiStreamCount = 8
let wtBidiPayloadSize = 512 * 1024                   // 512 KB per bidi stream
let wtUniStreamCount = 4
let wtUniPayloadSize = 256 * 1024                    // 256 KB per uni stream
let wtChunkSize = 16 * 1024                          // 16 KB write chunks

/// WebTransport datagram config
let wtDatagramCount = 10_000
let wtDatagramPayloadSize = 1024                     // 1 KB per datagram
let wtDatagramCollectTimeout: Duration = .seconds(5)

/// QUIC transport limits (must match or exceed server)
let maxStreamsBidi: UInt64 = 1024
let maxStreamsUni: UInt64 = 1024
let maxData: UInt64 = 100_000_000
let maxStreamData: UInt64 = 16_000_000
let clientIdleTimeout: Duration = .seconds(120)

// =============================================================================
// MARK: - Logging
// =============================================================================

func log(_ tag: String, _ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    print("[\(ts)] [\(tag)] \(message)")
}

// =============================================================================
// MARK: - Formatting
// =============================================================================

func formatBytes(_ bytes: UInt64) -> String {
    let b = Double(bytes)
    if b >= 1_073_741_824 { return String(format: "%.2f GB", b / 1_073_741_824) }
    if b >= 1_048_576 { return String(format: "%.2f MB", b / 1_048_576) }
    if b >= 1024 { return String(format: "%.2f KB", b / 1024) }
    return "\(bytes) B"
}

func formatRate(_ bytesPerSec: Double) -> String {
    if bytesPerSec >= 1_073_741_824 { return String(format: "%.2f GB/s", bytesPerSec / 1_073_741_824) }
    if bytesPerSec >= 1_048_576 { return String(format: "%.2f MB/s", bytesPerSec / 1_048_576) }
    if bytesPerSec >= 1024 { return String(format: "%.2f KB/s", bytesPerSec / 1024) }
    return String(format: "%.0f B/s", bytesPerSec)
}

func formatDuration(_ d: Duration) -> String {
    let ns = d.components.seconds * 1_000_000_000 + Int64(d.components.attoseconds / 1_000_000_000)
    let ms = Double(ns) / 1_000_000
    if ms >= 1000 { return String(format: "%.2f s", ms / 1000) }
    return String(format: "%.2f ms", ms)
}

func durationSeconds(_ d: Duration) -> Double {
    let ns = d.components.seconds * 1_000_000_000 + Int64(d.components.attoseconds / 1_000_000_000)
    return Double(ns) / 1_000_000_000
}

// =============================================================================
// MARK: - Process Metrics
// =============================================================================

struct ProcessMetrics: Sendable {
    let residentMemoryMB: Double
    let userCPUSeconds: Double
    let systemCPUSeconds: Double

    static func capture() -> ProcessMetrics {
        var usage = rusage()
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        getrusage(RUSAGE_SELF, &usage)
        let residentMB = Double(usage.ru_maxrss) / 1024.0 / 1024.0   // KB on macOS
        #else
        getrusage(0, &usage)  // RUSAGE_SELF == 0
        let residentMB = Double(usage.ru_maxrss) / (1024.0 * 1024.0) // bytes on Linux
        #endif
        let userCPU = Double(usage.ru_utime.tv_sec) + Double(usage.ru_utime.tv_usec) / 1_000_000
        let sysCPU = Double(usage.ru_stime.tv_sec) + Double(usage.ru_stime.tv_usec) / 1_000_000
        return ProcessMetrics(residentMemoryMB: residentMB, userCPUSeconds: userCPU, systemCPUSeconds: sysCPU)
    }

    func delta(from baseline: ProcessMetrics) -> String {
        let dMem = residentMemoryMB - baseline.residentMemoryMB
        let dUser = userCPUSeconds - baseline.userCPUSeconds
        let dSys = systemCPUSeconds - baseline.systemCPUSeconds
        return String(format: "Memory: +%.1f MB | CPU user: +%.3fs sys: +%.3fs", max(0, dMem), dUser, dSys)
    }
}

// =============================================================================
// MARK: - Result Accumulator
// =============================================================================

struct BenchResult: Sendable {
    let name: String
    let duration: Duration
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let operations: UInt64
    let errors: UInt64
    let integrityPass: Bool?
    let extra: String
}

final class ResultCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var results: [BenchResult] = []

    func add(_ r: BenchResult) { lock.lock(); results.append(r); lock.unlock() }

    func printReport() {
        lock.lock()
        let all = results
        lock.unlock()

        print("")
        print("=================================================================")
        print("  QUIVER BENCHMARK RESULTS")
        print("=================================================================")
        print("")

        let col1 = 36  // name
        let col2 = 12  // time
        let col3 = 14  // throughput
        let col4 = 10  // ops
        let col5 = 8   // errors
        let col6 = 10  // integrity

        func rpad(_ s: String, _ w: Int) -> String {
            s.count >= w ? s : s + String(repeating: " ", count: w - s.count)
        }

        let header = rpad("Test", col1) + rpad("Time", col2) + rpad("Throughput", col3) + rpad("Ops", col4) + rpad("Errors", col5) + rpad("Integrity", col6)
        let sep = String(repeating: "-", count: header.count)
        print(header)
        print(sep)

        for r in all {
            let totalBytes = r.bytesSent + r.bytesReceived
            let secs = durationSeconds(r.duration)
            let rate = secs > 0 ? Double(totalBytes) / secs : 0
            let integrity: String
            if let p = r.integrityPass {
                integrity = p ? "PASS" : "FAIL"
            } else {
                integrity = "N/A"
            }

            let line = rpad(r.name, col1)
                + rpad(formatDuration(r.duration), col2)
                + rpad(formatRate(rate), col3)
                + rpad("\(r.operations)", col4)
                + rpad("\(r.errors)", col5)
                + rpad(integrity, col6)
            print(line)
            if !r.extra.isEmpty {
                print("  \(r.extra)")
            }
        }

        print(sep)
        let totalSent = all.reduce(UInt64(0)) { $0 + $1.bytesSent }
        let totalRecv = all.reduce(UInt64(0)) { $0 + $1.bytesReceived }
        let totalErr = all.reduce(UInt64(0)) { $0 + $1.errors }
        print("Total sent: \(formatBytes(totalSent)) | Total received: \(formatBytes(totalRecv)) | Total errors: \(totalErr)")
        print("=================================================================")
    }
}

let collector = ResultCollector()

// =============================================================================
// MARK: - TLS Configuration
// =============================================================================

func makeClientTLSConfig(caCertPath: String?, alpn: String) throws -> TLSConfiguration {
    if let caCertPath = caCertPath {
        var tlsConfig = TLSConfiguration.client(
            serverName: "localhost",
            alpnProtocols: [alpn]
        )
        try tlsConfig.loadTrustedCAs(fromPEMFile: caCertPath)
        tlsConfig.verifyPeer = true
        tlsConfig.allowSelfSigned = false
        return tlsConfig
    } else {
        var tlsConfig = TLSConfiguration.client(
            serverName: "localhost",
            alpnProtocols: [alpn]
        )
        tlsConfig.verifyPeer = false
        tlsConfig.allowSelfSigned = true
        return tlsConfig
    }
}

/// Build QUICConfiguration for HTTP/3 + WebTransport (Phases 2, 3, 4)
func makeH3Config(caCertPath: String?) throws -> QUICConfiguration {
    let tlsConfig = try makeClientTLSConfig(caCertPath: caCertPath, alpn: h3ALPN)
    let isProduction = (caCertPath != nil)

    var config: QUICConfiguration
    if isProduction {
        config = QUICConfiguration.production {
            TLS13Handler(configuration: tlsConfig)
        }
    } else {
        config = QUICConfiguration.development {
            TLS13Handler(configuration: tlsConfig)
        }
    }

    config.alpn = [h3ALPN]
    config.maxIdleTimeout = clientIdleTimeout
    config.initialMaxStreamsBidi = maxStreamsBidi
    config.initialMaxStreamsUni = maxStreamsUni
    config.initialMaxData = maxData
    config.initialMaxStreamDataBidiLocal = maxStreamData
    config.initialMaxStreamDataBidiRemote = maxStreamData
    config.initialMaxStreamDataUni = maxStreamData
    config.enableDatagrams = true
    config.maxDatagramFrameSize = 65535
    config.maxUDPPayloadSize = 1452
    return config
}

/// Build QUICConfiguration for raw QUIC echo (Phase 1)
func makeRawQUICConfig(caCertPath: String?) throws -> QUICConfiguration {
    let tlsConfig = try makeClientTLSConfig(caCertPath: caCertPath, alpn: quicBenchALPN)
    let isProduction = (caCertPath != nil)

    var config: QUICConfiguration
    if isProduction {
        config = QUICConfiguration.production {
            TLS13Handler(configuration: tlsConfig)
        }
    } else {
        config = QUICConfiguration.development {
            TLS13Handler(configuration: tlsConfig)
        }
    }

    config.alpn = [quicBenchALPN]
    config.maxIdleTimeout = clientIdleTimeout
    config.initialMaxStreamsBidi = maxStreamsBidi
    config.initialMaxStreamsUni = maxStreamsUni
    config.initialMaxData = maxData
    config.initialMaxStreamDataBidiLocal = maxStreamData
    config.initialMaxStreamDataBidiRemote = maxStreamData
    config.initialMaxStreamDataUni = maxStreamData
    config.enableDatagrams = false
    config.maxUDPPayloadSize = 1452
    return config
}

// =============================================================================
// MARK: - Data Generation
// =============================================================================

/// Generates deterministic payload for integrity checks
func generatePayload(size: Int, seed: UInt8 = 0) -> Data {
    var data = Data(count: size)
    for i in 0..<size {
        data[i] = UInt8((Int(seed) &+ i) & 0xFF)
    }
    return data
}

// =============================================================================
// MARK: - Phase 1: QUIC Raw Stream Throughput
// =============================================================================

func runQUICBenchmark(caCertPath: String?) async throws {
    log("QUIC", "--- Phase 1: QUIC Raw Stream Throughput ---")
    log("QUIC", "")

    let config = try makeRawQUICConfig(caCertPath: caCertPath)
    let endpoint = QUICEndpoint(configuration: config)
    let serverAddress = QUIC.SocketAddress(ipAddress: benchHost, port: quicPort)

    log("QUIC", "Dialing \(benchHost):\(quicPort) (ALPN: \(quicBenchALPN))...")
    let conn = try await endpoint.dial(address: serverAddress, timeout: .seconds(10))
    log("QUIC", "Connected. Local: \(conn.localAddress?.description ?? "?") Remote: \(conn.remoteAddress)")

    // -- Unidirectional bulk upload --
    log("QUIC", "")
    log("QUIC", "[1a] Unidirectional bulk upload: \(quicBulkStreamCount) streams x \(formatBytes(UInt64(quicBulkBytesPerStream)))")
    let baselineUni = ProcessMetrics.capture()
    let chunkData = generatePayload(size: quicChunkSize, seed: 0xAB)
    let uniStart = ContinuousClock.now

    var uniBytesSent: UInt64 = 0
    var uniErrors: UInt64 = 0

    await withTaskGroup(of: (UInt64, UInt64).self) { group in
        for _ in 0..<quicBulkStreamCount {
            group.addTask {
                var sent: UInt64 = 0
                var errs: UInt64 = 0
                do {
                    let stream = try await conn.openUniStream()
                    var remaining = quicBulkBytesPerStream
                    while remaining > 0 {
                        let toSend = min(remaining, quicChunkSize)
                        let slice = chunkData.prefix(toSend)
                        try await stream.write(Data(slice))
                        sent += UInt64(toSend)
                        remaining -= toSend
                    }
                    try await stream.closeWrite()
                } catch {
                    errs += 1
                }
                return (sent, errs)
            }
        }
        for await (s, e) in group {
            uniBytesSent += s
            uniErrors += e
        }
    }

    let uniDuration = ContinuousClock.now - uniStart
    let uniMetrics = ProcessMetrics.capture()
    let uniRate = durationSeconds(uniDuration) > 0 ? Double(uniBytesSent) / durationSeconds(uniDuration) : 0
    log("QUIC", "  Sent: \(formatBytes(uniBytesSent)) in \(formatDuration(uniDuration)) (\(formatRate(uniRate)))")
    log("QUIC", "  \(uniMetrics.delta(from: baselineUni))")

    collector.add(BenchResult(
        name: "QUIC Uni Bulk Upload",
        duration: uniDuration,
        bytesSent: uniBytesSent, bytesReceived: 0,
        operations: UInt64(quicBulkStreamCount),
        errors: uniErrors, integrityPass: nil,
        extra: "\(quicBulkStreamCount) streams x \(formatBytes(UInt64(quicBulkBytesPerStream)))"
    ))

    try await Task.sleep(for: .milliseconds(200))

    // -- Bidirectional echo throughput --
    log("QUIC", "")
    log("QUIC", "[1b] Bidirectional echo: \(quicBidiStreamCount) streams x \(formatBytes(UInt64(quicBidiBytesPerStream)))")
    let baselineBidi = ProcessMetrics.capture()
    let bidiStart = ContinuousClock.now

    var bidiBytesSent: UInt64 = 0
    var bidiBytesRecv: UInt64 = 0
    var bidiErrors: UInt64 = 0

    await withTaskGroup(of: (UInt64, UInt64, UInt64).self) { group in
        for _ in 0..<quicBidiStreamCount {
            group.addTask {
                var sent: UInt64 = 0
                var recv: UInt64 = 0
                var errs: UInt64 = 0
                do {
                    let stream = try await conn.openStream()
                    var remaining = quicBidiBytesPerStream
                    while remaining > 0 {
                        let toSend = min(remaining, quicChunkSize)
                        let slice = chunkData.prefix(toSend)
                        try await stream.write(Data(slice))
                        sent += UInt64(toSend)
                        remaining -= toSend

                        // Read echo
                        let echo = try await stream.read()
                        recv += UInt64(echo.count)
                    }
                    try await stream.closeWrite()
                    // Drain remaining echo data
                    while true {
                        let d = try await stream.read()
                        if d.isEmpty { break }
                        recv += UInt64(d.count)
                    }
                } catch {
                    errs += 1
                }
                return (sent, recv, errs)
            }
        }
        for await (s, r, e) in group {
            bidiBytesSent += s
            bidiBytesRecv += r
            bidiErrors += e
        }
    }

    let bidiDuration = ContinuousClock.now - bidiStart
    let bidiMetrics = ProcessMetrics.capture()
    let bidiTotalBytes = bidiBytesSent + bidiBytesRecv
    let bidiRate = durationSeconds(bidiDuration) > 0 ? Double(bidiTotalBytes) / durationSeconds(bidiDuration) : 0
    log("QUIC", "  Sent: \(formatBytes(bidiBytesSent)) Received: \(formatBytes(bidiBytesRecv))")
    log("QUIC", "  Combined: \(formatBytes(UInt64(bidiTotalBytes))) in \(formatDuration(bidiDuration)) (\(formatRate(bidiRate)))")
    log("QUIC", "  \(bidiMetrics.delta(from: baselineBidi))")

    collector.add(BenchResult(
        name: "QUIC Bidi Echo",
        duration: bidiDuration,
        bytesSent: bidiBytesSent, bytesReceived: bidiBytesRecv,
        operations: UInt64(quicBidiStreamCount),
        errors: bidiErrors, integrityPass: nil,
        extra: "\(quicBidiStreamCount) streams x \(formatBytes(UInt64(quicBidiBytesPerStream)))"
    ))

    // Cleanup
    await conn.close(error: nil)
    await endpoint.stop()
    log("QUIC", "Connection closed.")
}

// =============================================================================
// MARK: - Phase 2: HTTP/3 Benchmark
// =============================================================================

func runHTTP3Benchmark(caCertPath: String?) async throws {
    log("HTTP3", "--- Phase 2: HTTP/3 Variable Payload Benchmark ---")
    log("HTTP3", "")

    let config = try makeH3Config(caCertPath: caCertPath)
    let endpoint = QUICEndpoint(configuration: config)
    let serverAddress = QUIC.SocketAddress(ipAddress: benchHost, port: h3Port)

    log("HTTP3", "Dialing \(benchHost):\(h3Port)...")
    let quicConn = try await endpoint.dial(address: serverAddress, timeout: .seconds(10))
    log("HTTP3", "QUIC connected.")

    let h3Conn = HTTP3Connection(
        quicConnection: quicConn,
        role: .client,
        settings: HTTP3Settings.literalOnly
    )
    try await h3Conn.initialize()
    try await h3Conn.waitForReady(timeout: .seconds(5))
    log("HTTP3", "HTTP/3 ready.")
    log("HTTP3", "")

    let authority = "\(benchHost):\(h3Port)"

    // -- GET /bench/html --
    log("HTTP3", "[2a] GET /bench/html x \(h3Iterations)")
    let baselineHTML = ProcessMetrics.capture()
    let htmlStart = ContinuousClock.now
    var htmlBytesRecv: UInt64 = 0
    var htmlErrors: UInt64 = 0

    for _ in 0..<h3Iterations {
        do {
            let resp = try await h3Conn.sendRequest(HTTP3Request(
                method: .get, scheme: "https", authority: authority, path: "/bench/html"
            ))
            htmlBytesRecv += UInt64(resp.body.count)
            if !resp.isSuccess { htmlErrors += 1 }
        } catch {
            htmlErrors += 1
        }
    }

    let htmlDuration = ContinuousClock.now - htmlStart
    let htmlMetrics = ProcessMetrics.capture()
    log("HTTP3", "  Received: \(formatBytes(htmlBytesRecv)) in \(formatDuration(htmlDuration))")
    log("HTTP3", "  \(htmlMetrics.delta(from: baselineHTML))")

    collector.add(BenchResult(
        name: "HTTP/3 GET /bench/html",
        duration: htmlDuration,
        bytesSent: 0, bytesReceived: htmlBytesRecv,
        operations: UInt64(h3Iterations),
        errors: htmlErrors, integrityPass: nil,
        extra: "~64KB HTML page x \(h3Iterations)"
    ))

    try await Task.sleep(for: .milliseconds(100))

    // -- GET /bench/headers --
    log("HTTP3", "")
    log("HTTP3", "[2b] GET /bench/headers x \(h3Iterations)")
    let baselineHdr = ProcessMetrics.capture()
    let hdrStart = ContinuousClock.now
    var hdrBytesRecv: UInt64 = 0
    var hdrErrors: UInt64 = 0
    var maxHeaderCount: Int = 0

    for _ in 0..<h3Iterations {
        do {
            let resp = try await h3Conn.sendRequest(HTTP3Request(
                method: .get, scheme: "https", authority: authority, path: "/bench/headers"
            ))
            hdrBytesRecv += UInt64(resp.body.count)
            maxHeaderCount = max(maxHeaderCount, resp.headers.count)
            if !resp.isSuccess { hdrErrors += 1 }
        } catch {
            hdrErrors += 1
        }
    }

    let hdrDuration = ContinuousClock.now - hdrStart
    let hdrMetrics = ProcessMetrics.capture()
    log("HTTP3", "  Received: \(formatBytes(hdrBytesRecv)) in \(formatDuration(hdrDuration)), max headers: \(maxHeaderCount)")
    log("HTTP3", "  \(hdrMetrics.delta(from: baselineHdr))")

    collector.add(BenchResult(
        name: "HTTP/3 GET /bench/headers",
        duration: hdrDuration,
        bytesSent: 0, bytesReceived: hdrBytesRecv,
        operations: UInt64(h3Iterations),
        errors: hdrErrors, integrityPass: nil,
        extra: "200+ response headers x \(h3Iterations)"
    ))

    try await Task.sleep(for: .milliseconds(100))

    // -- GET /bench/large-body --
    log("HTTP3", "")
    log("HTTP3", "[2c] GET /bench/large-body x \(h3Iterations)")
    let baselineLarge = ProcessMetrics.capture()
    let largeStart = ContinuousClock.now
    var largeBytesRecv: UInt64 = 0
    var largeErrors: UInt64 = 0
    var largeIntegrity = true

    for _ in 0..<h3Iterations {
        do {
            let resp = try await h3Conn.sendRequest(HTTP3Request(
                method: .get, scheme: "https", authority: authority, path: "/bench/large-body"
            ))
            largeBytesRecv += UInt64(resp.body.count)
            if !resp.isSuccess { largeErrors += 1 }
            // Verify integrity: first 256 bytes should be 0x00..0xFF
            if resp.body.count >= 256 {
                for i in 0..<256 {
                    if resp.body[i] != UInt8(i & 0xFF) {
                        largeIntegrity = false
                        break
                    }
                }
            }
        } catch {
            largeErrors += 1
        }
    }

    let largeDuration = ContinuousClock.now - largeStart
    let largeMetrics = ProcessMetrics.capture()
    log("HTTP3", "  Received: \(formatBytes(largeBytesRecv)) in \(formatDuration(largeDuration))")
    log("HTTP3", "  Integrity: \(largeIntegrity ? "PASS" : "FAIL")")
    log("HTTP3", "  \(largeMetrics.delta(from: baselineLarge))")

    collector.add(BenchResult(
        name: "HTTP/3 GET /bench/large-body",
        duration: largeDuration,
        bytesSent: 0, bytesReceived: largeBytesRecv,
        operations: UInt64(h3Iterations),
        errors: largeErrors, integrityPass: largeIntegrity,
        extra: "~4MB body x \(h3Iterations)"
    ))

    try await Task.sleep(for: .milliseconds(100))

    // -- POST /bench/echo --
    log("HTTP3", "")
    log("HTTP3", "[2d] POST /bench/echo x \(h3Iterations)")
    let echoPayload = generatePayload(size: h3EchoBodySize, seed: 0x42)
    let baselineEcho = ProcessMetrics.capture()
    let echoStart = ContinuousClock.now
    var echoBytesSent: UInt64 = 0
    var echoBytesRecv: UInt64 = 0
    var echoErrors: UInt64 = 0
    var echoIntegrity = true

    for _ in 0..<h3Iterations {
        do {
            let resp = try await h3Conn.sendRequest(HTTP3Request(
                method: .post, scheme: "https", authority: authority, path: "/bench/echo",
                headers: [("content-type", "application/octet-stream")],
                body: echoPayload
            ))
            echoBytesSent += UInt64(echoPayload.count)
            echoBytesRecv += UInt64(resp.body.count)
            if !resp.isSuccess { echoErrors += 1 }
            if resp.body != echoPayload {
                echoIntegrity = false
            }
        } catch {
            echoErrors += 1
        }
    }

    let echoDuration = ContinuousClock.now - echoStart
    let echoMetrics = ProcessMetrics.capture()
    log("HTTP3", "  Sent: \(formatBytes(echoBytesSent)) Received: \(formatBytes(echoBytesRecv)) in \(formatDuration(echoDuration))")
    log("HTTP3", "  Integrity: \(echoIntegrity ? "PASS" : "FAIL")")
    log("HTTP3", "  \(echoMetrics.delta(from: baselineEcho))")

    collector.add(BenchResult(
        name: "HTTP/3 POST /bench/echo",
        duration: echoDuration,
        bytesSent: echoBytesSent, bytesReceived: echoBytesRecv,
        operations: UInt64(h3Iterations),
        errors: echoErrors, integrityPass: echoIntegrity,
        extra: "\(formatBytes(UInt64(h3EchoBodySize))) echo x \(h3Iterations)"
    ))

    try await Task.sleep(for: .milliseconds(100))

    // -- POST /bench/sink (upload throughput) --
    log("HTTP3", "")
    log("HTTP3", "[2e] POST /bench/sink x \(h3Iterations)")
    let sinkPayload = generatePayload(size: h3UploadBodySize, seed: 0xBB)
    let baselineSink = ProcessMetrics.capture()
    let sinkStart = ContinuousClock.now
    var sinkBytesSent: UInt64 = 0
    var sinkErrors: UInt64 = 0

    for _ in 0..<h3Iterations {
        do {
            let resp = try await h3Conn.sendRequest(HTTP3Request(
                method: .post, scheme: "https", authority: authority, path: "/bench/sink",
                headers: [("content-type", "application/octet-stream")],
                body: sinkPayload
            ))
            sinkBytesSent += UInt64(sinkPayload.count)
            if resp.status != 204 { sinkErrors += 1 }
        } catch {
            sinkErrors += 1
        }
    }

    let sinkDuration = ContinuousClock.now - sinkStart
    let sinkMetrics = ProcessMetrics.capture()
    log("HTTP3", "  Sent: \(formatBytes(sinkBytesSent)) in \(formatDuration(sinkDuration))")
    log("HTTP3", "  \(sinkMetrics.delta(from: baselineSink))")

    collector.add(BenchResult(
        name: "HTTP/3 POST /bench/sink",
        duration: sinkDuration,
        bytesSent: sinkBytesSent, bytesReceived: 0,
        operations: UInt64(h3Iterations),
        errors: sinkErrors, integrityPass: nil,
        extra: "\(formatBytes(UInt64(h3UploadBodySize))) upload x \(h3Iterations)"
    ))

    // Cleanup
    await h3Conn.close()
    await quicConn.close(error: nil)
    await endpoint.stop()
    log("HTTP3", "Connection closed.")
}

// =============================================================================
// MARK: - Phase 3: WebTransport Stream Reliability
// =============================================================================

func runWebTransportStreamBenchmark(caCertPath: String?) async throws {
    log("WT-S", "--- Phase 3: WebTransport Stream Reliability ---")
    log("WT-S", "")

    let config = try makeH3Config(caCertPath: caCertPath)
    let endpoint = QUICEndpoint(configuration: config)
    let serverAddress = QUIC.SocketAddress(ipAddress: benchHost, port: h3Port)

    log("WT-S", "Dialing \(benchHost):\(h3Port)...")
    let quicConn = try await endpoint.dial(address: serverAddress, timeout: .seconds(10))
    log("WT-S", "QUIC connected.")

    let wtClient = WebTransportClient(
        quicConnection: quicConn,
        configuration: WebTransportClient.Configuration(
            maxSessions: 1,
            connectionReadyTimeout: .seconds(10),
            connectTimeout: .seconds(10)
        )
    )
    try await wtClient.initialize()
    log("WT-S", "HTTP/3 + WebTransport layer ready.")

    let session = try await wtClient.connect(
        authority: "\(benchHost):\(h3Port)",
        path: "/bench"
    )
    log("WT-S", "WebTransport session established (ID: \(await session.sessionID)).")
    log("WT-S", "")

    try await Task.sleep(for: .milliseconds(200))

    // -- Bidi stream reliability --
    log("WT-S", "[3a] Bidi stream reliability: \(wtBidiStreamCount) streams x \(formatBytes(UInt64(wtBidiPayloadSize)))")
    let baselineBidi = ProcessMetrics.capture()
    let bidiStart = ContinuousClock.now

    var bidiBytesSent: UInt64 = 0
    var bidiBytesRecv: UInt64 = 0
    var bidiErrors: UInt64 = 0
    var bidiIntegrity = true

    await withTaskGroup(of: (UInt64, UInt64, UInt64, Bool).self) { group in
        for i in 0..<wtBidiStreamCount {
            group.addTask {
                var sent: UInt64 = 0
                var recv: UInt64 = 0
                var errs: UInt64 = 0
                var integrity = true
                do {
                    let payload = generatePayload(size: wtBidiPayloadSize, seed: UInt8(i & 0xFF))
                    let stream = try await session.openBidirectionalStream()

                    // Write in chunks
                    var offset = 0
                    while offset < payload.count {
                        let end = min(offset + wtChunkSize, payload.count)
                        let chunk = Data(payload[offset..<end])
                        try await stream.write(chunk)
                        sent += UInt64(chunk.count)
                        offset = end
                    }
                    try await stream.closeWrite()

                    // Read all echoed data
                    var received = Data()
                    while true {
                        let d = try await stream.read()
                        if d.isEmpty { break }
                        received.append(d)
                    }
                    recv = UInt64(received.count)

                    // Integrity check
                    if received != payload {
                        integrity = false
                    }
                } catch {
                    errs += 1
                    integrity = false
                }
                return (sent, recv, errs, integrity)
            }
        }
        for await (s, r, e, ok) in group {
            bidiBytesSent += s
            bidiBytesRecv += r
            bidiErrors += e
            if !ok { bidiIntegrity = false }
        }
    }

    let bidiDuration = ContinuousClock.now - bidiStart
    let bidiMetrics = ProcessMetrics.capture()
    log("WT-S", "  Sent: \(formatBytes(bidiBytesSent)) Received: \(formatBytes(bidiBytesRecv))")
    log("WT-S", "  Duration: \(formatDuration(bidiDuration))")
    log("WT-S", "  Integrity: \(bidiIntegrity ? "PASS" : "FAIL")")
    log("WT-S", "  \(bidiMetrics.delta(from: baselineBidi))")

    collector.add(BenchResult(
        name: "WT Bidi Stream Reliability",
        duration: bidiDuration,
        bytesSent: bidiBytesSent, bytesReceived: bidiBytesRecv,
        operations: UInt64(wtBidiStreamCount),
        errors: bidiErrors, integrityPass: bidiIntegrity,
        extra: "\(wtBidiStreamCount) streams x \(formatBytes(UInt64(wtBidiPayloadSize)))"
    ))

    try await Task.sleep(for: .milliseconds(200))

    // -- Uni stream reliability --
    log("WT-S", "")
    log("WT-S", "[3b] Uni stream reliability: \(wtUniStreamCount) streams x \(formatBytes(UInt64(wtUniPayloadSize)))")
    let baselineUni = ProcessMetrics.capture()
    let uniStart = ContinuousClock.now

    var uniBytesSent: UInt64 = 0
    var uniBytesRecv: UInt64 = 0
    var uniErrors: UInt64 = 0
    var uniIntegrity = true

    // For uni streams, we need to send on an outgoing uni and receive on incoming uni
    // We do them sequentially to match the echo pattern
    for i in 0..<wtUniStreamCount {
        let payload = generatePayload(size: wtUniPayloadSize, seed: UInt8((i + 128) & 0xFF))

        // Set up receiver before sending
        let receiveTask = Task<Data, Error> {
            var iterator = await session.incomingUnidirectionalStreams.makeAsyncIterator()
            guard let responseStream = await iterator.next() else {
                throw BenchError.noResponseStream
            }
            var received = Data()
            while true {
                let chunk = try await responseStream.read()
                if chunk.isEmpty { break }
                received.append(chunk)
            }
            return received
        }

        do {
            let sendStream = try await session.openUnidirectionalStream()
            var offset = 0
            while offset < payload.count {
                let end = min(offset + wtChunkSize, payload.count)
                let chunk = Data(payload[offset..<end])
                try await sendStream.write(chunk)
                uniBytesSent += UInt64(chunk.count)
                offset = end
            }
            try await sendStream.closeWrite()

            // Wait for response with timeout
            let received = try await withThrowingTaskGroup(of: Data.self) { group in
                group.addTask {
                    try await receiveTask.value
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw BenchError.timeout
                }
                let result = try await group.next()!
                group.cancelAll()
                return result
            }

            uniBytesRecv += UInt64(received.count)
            if received != payload {
                uniIntegrity = false
                log("WT-S", "  Stream #\(i): INTEGRITY FAIL (sent \(payload.count), received \(received.count))")
            }
        } catch {
            uniErrors += 1
            uniIntegrity = false
            receiveTask.cancel()
            log("WT-S", "  Stream #\(i) error: \(error)")
        }
    }

    let uniDuration = ContinuousClock.now - uniStart
    let uniMetrics = ProcessMetrics.capture()
    log("WT-S", "  Sent: \(formatBytes(uniBytesSent)) Received: \(formatBytes(uniBytesRecv))")
    log("WT-S", "  Duration: \(formatDuration(uniDuration))")
    log("WT-S", "  Integrity: \(uniIntegrity ? "PASS" : "FAIL")")
    log("WT-S", "  \(uniMetrics.delta(from: baselineUni))")

    collector.add(BenchResult(
        name: "WT Uni Stream Reliability",
        duration: uniDuration,
        bytesSent: uniBytesSent, bytesReceived: uniBytesRecv,
        operations: UInt64(wtUniStreamCount),
        errors: uniErrors, integrityPass: uniIntegrity,
        extra: "\(wtUniStreamCount) streams x \(formatBytes(UInt64(wtUniPayloadSize)))"
    ))

    // Cleanup
    try await session.close()
    await wtClient.close()
    await endpoint.stop()
    log("WT-S", "Session closed.")
}

// =============================================================================
// MARK: - Phase 4: WebTransport Datagram Throughput
// =============================================================================

func runWebTransportDatagramBenchmark(caCertPath: String?) async throws {
    log("WT-D", "--- Phase 4: WebTransport Datagram Throughput ---")
    log("WT-D", "")

    let config = try makeH3Config(caCertPath: caCertPath)
    let endpoint = QUICEndpoint(configuration: config)
    let serverAddress = QUIC.SocketAddress(ipAddress: benchHost, port: h3Port)

    log("WT-D", "Dialing \(benchHost):\(h3Port)...")
    let quicConn = try await endpoint.dial(address: serverAddress, timeout: .seconds(10))
    log("WT-D", "QUIC connected.")

    let wtClient = WebTransportClient(
        quicConnection: quicConn,
        configuration: WebTransportClient.Configuration(
            maxSessions: 1,
            connectionReadyTimeout: .seconds(10),
            connectTimeout: .seconds(10)
        )
    )
    try await wtClient.initialize()

    let session = try await wtClient.connect(
        authority: "\(benchHost):\(h3Port)",
        path: "/bench"
    )
    log("WT-D", "WebTransport session established.")
    log("WT-D", "")

    try await Task.sleep(for: .milliseconds(200))

    log("WT-D", "[4] Datagram blast: \(wtDatagramCount) datagrams x \(formatBytes(UInt64(wtDatagramPayloadSize)))")
    let baselineDg = ProcessMetrics.capture()

    // Receiver task: collect echoed datagrams
    let receiverTask = Task<(Int, UInt64), Never> {
        var count = 0
        var totalBytes: UInt64 = 0
        for await datagram in await session.incomingDatagrams {
            count += 1
            totalBytes += UInt64(datagram.count)
            if count >= wtDatagramCount {
                break
            }
        }
        return (count, totalBytes)
    }

    // Small delay to ensure receiver is active
    try await Task.sleep(for: .milliseconds(50))

    // Send phase
    let sendStart = ContinuousClock.now
    var sendCount: UInt64 = 0
    var sendErrors: UInt64 = 0
    var sendBytes: UInt64 = 0

    for i in 0..<wtDatagramCount {
        // Build payload with sequence number for potential ordering analysis
        var payload = Data(count: wtDatagramPayloadSize)
        // Write sequence number in first 4 bytes (big-endian)
        let seq = UInt32(i)
        payload[0] = UInt8((seq >> 24) & 0xFF)
        payload[1] = UInt8((seq >> 16) & 0xFF)
        payload[2] = UInt8((seq >> 8) & 0xFF)
        payload[3] = UInt8(seq & 0xFF)
        // Fill rest with pattern
        for j in 4..<wtDatagramPayloadSize {
            payload[j] = UInt8(j & 0xFF)
        }

        do {
            try await session.sendDatagram(payload)
            sendCount += 1
            sendBytes += UInt64(payload.count)
        } catch {
            sendErrors += 1
        }
    }

    let sendDuration = ContinuousClock.now - sendStart
    let sendRate = durationSeconds(sendDuration) > 0 ? Double(sendBytes) / durationSeconds(sendDuration) : 0
    log("WT-D", "  Send phase: \(sendCount) sent, \(sendErrors) failed in \(formatDuration(sendDuration)) (\(formatRate(sendRate)))")

    // Wait for echoes with timeout
    log("WT-D", "  Waiting for echoes (timeout: \(wtDatagramCollectTimeout))...")

    let (recvCount, recvBytes): (Int, UInt64)
    do {
        (recvCount, recvBytes) = try await withThrowingTaskGroup(of: (Int, UInt64).self) { group in
            group.addTask {
                await receiverTask.value
            }
            group.addTask {
                try await Task.sleep(for: wtDatagramCollectTimeout)
                return (-1, UInt64(0)) // timeout sentinel
            }
            let result = try await group.next() ?? (-1, 0)
            group.cancelAll()
            return result
        }
    } catch {
        receiverTask.cancel()
        (recvCount, recvBytes) = (0, 0)
    }

    receiverTask.cancel()

    let totalDuration = ContinuousClock.now - sendStart
    let dgMetrics = ProcessMetrics.capture()

    let actualRecv = recvCount == -1 ? 0 : recvCount
    let lossRate = sendCount > 0 ? Double(Int(sendCount) - actualRecv) / Double(sendCount) * 100 : 0
    let recvRate = durationSeconds(totalDuration) > 0 ? Double(recvBytes) / durationSeconds(totalDuration) : 0

    log("WT-D", "")
    log("WT-D", "  ┌───────────────────────────────────────────────────┐")
    log("WT-D", "  │ DATAGRAM RESULTS                                  │")
    log("WT-D", "  ├───────────────────────────────────────────────────┤")
    log("WT-D", "  │ Sent:      \(String(format: "%-10d", sendCount)) (\(formatBytes(sendBytes)))")
    log("WT-D", "  │ Received:  \(String(format: "%-10d", actualRecv)) (\(formatBytes(recvBytes)))")
    log("WT-D", "  │ Lost:      \(String(format: "%-10d", Int(sendCount) - actualRecv)) (\(String(format: "%.1f%%", lossRate)))")
    log("WT-D", "  │ Send rate: \(formatRate(sendRate))")
    log("WT-D", "  │ Recv rate: \(formatRate(recvRate))")
    log("WT-D", "  │ Duration:  \(formatDuration(totalDuration))")
    log("WT-D", "  └───────────────────────────────────────────────────┘")
    log("WT-D", "  \(dgMetrics.delta(from: baselineDg))")

    collector.add(BenchResult(
        name: "WT Datagram Throughput",
        duration: totalDuration,
        bytesSent: sendBytes, bytesReceived: recvBytes,
        operations: sendCount,
        errors: sendErrors + UInt64(max(0, Int(sendCount) - actualRecv)),
        integrityPass: nil,
        extra: "sent=\(sendCount) recv=\(actualRecv) loss=\(String(format: "%.1f%%", lossRate))"
    ))

    // Cleanup
    try await session.close()
    await wtClient.close()
    await endpoint.stop()
    log("WT-D", "Session closed.")
}

// =============================================================================
// MARK: - Errors
// =============================================================================

enum BenchError: Error, CustomStringConvertible {
    case noResponseStream
    case timeout
    case integrityFailed

    var description: String {
        switch self {
        case .noResponseStream: return "No response uni stream received"
        case .timeout: return "Operation timed out"
        case .integrityFailed: return "Data integrity check failed"
        }
    }
}

// =============================================================================
// MARK: - Entrypoint
// =============================================================================

// Parse positional args: [ca-cert.pem] or no args
var caCertPath: String? = nil

let args = CommandLine.arguments.dropFirst()
let positional = Array(args)

if positional.count >= 1 {
    caCertPath = positional[0]
}

let overallBaseline = ProcessMetrics.capture()
let overallStart = ContinuousClock.now

print("")
print("=================================================================")
print("  Quiver Benchmark Client")
print("=================================================================")
print("  QUIC raw:  \(benchHost):\(quicPort)  (ALPN: \(quicBenchALPN))")
print("  HTTP/3+WT: \(benchHost):\(h3Port)  (ALPN: \(h3ALPN))")
if let ca = caCertPath {
    print("  TLS:       Production (CA: \(ca))")
} else {
    print("  TLS:       Development (self-signed)")
}
print("  Config:")
print("    QUIC bulk:  \(quicBulkStreamCount) uni x \(formatBytes(UInt64(quicBulkBytesPerStream))), \(quicBidiStreamCount) bidi x \(formatBytes(UInt64(quicBidiBytesPerStream)))")
print("    HTTP/3:     \(h3Iterations) iterations per endpoint")
print("    WT streams: \(wtBidiStreamCount) bidi x \(formatBytes(UInt64(wtBidiPayloadSize))), \(wtUniStreamCount) uni x \(formatBytes(UInt64(wtUniPayloadSize)))")
print("    WT dgrams:  \(wtDatagramCount) x \(formatBytes(UInt64(wtDatagramPayloadSize)))")
print("=================================================================")
print("")

do {
    // Phase 1: QUIC raw (port 4501, ALPN: quic-bench)
    do {
        try await runQUICBenchmark(caCertPath: caCertPath)
    } catch {
        log("QUIC", "Phase 1 FAILED: \(error)")
        collector.add(BenchResult(
            name: "QUIC (FAILED)", duration: .zero,
            bytesSent: 0, bytesReceived: 0, operations: 0,
            errors: 1, integrityPass: nil, extra: "\(error)"
        ))
    }

    print("")
    try await Task.sleep(for: .milliseconds(500))

    // Phase 2: HTTP/3 (port 4500, ALPN: h3)
    do {
        try await runHTTP3Benchmark(caCertPath: caCertPath)
    } catch {
        log("HTTP3", "Phase 2 FAILED: \(error)")
        collector.add(BenchResult(
            name: "HTTP/3 (FAILED)", duration: .zero,
            bytesSent: 0, bytesReceived: 0, operations: 0,
            errors: 1, integrityPass: nil, extra: "\(error)"
        ))
    }

    print("")
    try await Task.sleep(for: .milliseconds(500))

    // Phase 3: WebTransport streams (port 4500, ALPN: h3)
    do {
        try await runWebTransportStreamBenchmark(caCertPath: caCertPath)
    } catch {
        log("WT-S", "Phase 3 FAILED: \(error)")
        collector.add(BenchResult(
            name: "WT Streams (FAILED)", duration: .zero,
            bytesSent: 0, bytesReceived: 0, operations: 0,
            errors: 1, integrityPass: nil, extra: "\(error)"
        ))
    }

    print("")
    try await Task.sleep(for: .milliseconds(500))

    // Phase 4: WebTransport datagrams (port 4500, ALPN: h3)
    do {
        try await runWebTransportDatagramBenchmark(caCertPath: caCertPath)
    } catch {
        log("WT-D", "Phase 4 FAILED: \(error)")
        collector.add(BenchResult(
            name: "WT Datagrams (FAILED)", duration: .zero,
            bytesSent: 0, bytesReceived: 0, operations: 0,
            errors: 1, integrityPass: nil, extra: "\(error)"
        ))
    }

    // Final report
    let overallDuration = ContinuousClock.now - overallStart
    let overallFinal = ProcessMetrics.capture()

    print("")
    print("")
    collector.printReport()
    print("")
    print("Overall duration: \(formatDuration(overallDuration))")
    print("Process metrics:  \(overallFinal.delta(from: overallBaseline))")
    print("Peak memory:      \(String(format: "%.1f MB", overallFinal.residentMemoryMB))")
    print("Total CPU:        user \(String(format: "%.3fs", overallFinal.userCPUSeconds)) + sys \(String(format: "%.3fs", overallFinal.systemCPUSeconds))")
    print("")

} catch {
    log("Client", "FATAL: \(error)")
    exit(1)
}
