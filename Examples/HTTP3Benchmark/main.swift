import Foundation
import HTTP3
import Logging
import QUIC
import QUICCore
import QUICCrypto

let defaultHost = "127.0.0.1"
let defaultPort: UInt16 = 9443
let h3ALPN = "h3"

struct Arguments: Sendable {
    enum Mode: String, Sendable {
        case server
        case client
        case help
    }

    enum Workload: String, Sendable {
        case download
        case upload
        case ping
        case mixed
    }

    var mode: Mode = .help
    var workload: Workload = .download
    var host: String = defaultHost
    var port: UInt16 = defaultPort
    var shards: Int = 1
    var ports: Int = 1
    var durationSeconds: Int = 30
    var connections: Int = 96
    var concurrency: Int = 96
    var bytesPerRequest: Int = 64 * 1024
    var chunkSize: Int = 1200
    var socketBufferSize: Int = 16 * 1024 * 1024
    var initialMaxData: UInt64 = 512 * 1024 * 1024
    var initialMaxStreamData: UInt64 = 64 * 1024 * 1024
    var initialMaxStreamsBidi: UInt64 = 10_000
    var maxUDPPayloadSize: Int = 1200
    var certPath: String?
    var keyPath: String?
    var caCertPath: String?
    var serverName: String?
    var logLevel: Logger.Level = .warning

    static func parse() -> Arguments {
        var result = Arguments()
        let args = CommandLine.arguments
        var index = 1

        while index < args.count {
            let arg = args[index]
            switch arg {
            case "server":
                result.mode = .server
            case "client":
                result.mode = .client
            case "help", "--help", "-h":
                result.mode = .help
            case "--workload":
                index += 1
                if index < args.count, let workload = Workload(rawValue: args[index]) {
                    result.workload = workload
                }
            case "--host":
                index += 1
                if index < args.count { result.host = args[index] }
            case "--port", "-p":
                index += 1
                if index < args.count { result.port = UInt16(args[index]) ?? result.port }
            case "--shards":
                index += 1
                if index < args.count { result.shards = max(1, Int(args[index]) ?? result.shards) }
            case "--ports":
                index += 1
                if index < args.count { result.ports = max(1, Int(args[index]) ?? result.ports) }
            case "--duration":
                index += 1
                if index < args.count { result.durationSeconds = max(1, Int(args[index]) ?? result.durationSeconds) }
            case "--connections":
                index += 1
                if index < args.count { result.connections = max(1, Int(args[index]) ?? result.connections) }
            case "--concurrency":
                index += 1
                if index < args.count { result.concurrency = max(1, Int(args[index]) ?? result.concurrency) }
            case "--bytes":
                index += 1
                if index < args.count { result.bytesPerRequest = max(0, parseByteCount(args[index]) ?? result.bytesPerRequest) }
            case "--chunk-size":
                index += 1
                if index < args.count { result.chunkSize = max(1, parseByteCount(args[index]) ?? result.chunkSize) }
            case "--socket-buffer":
                index += 1
                if index < args.count { result.socketBufferSize = max(65_536, parseByteCount(args[index]) ?? result.socketBufferSize) }
            case "--initial-max-data":
                index += 1
                if index < args.count { result.initialMaxData = UInt64(parseByteCount(args[index]) ?? Int(result.initialMaxData)) }
            case "--initial-max-stream-data":
                index += 1
                if index < args.count { result.initialMaxStreamData = UInt64(parseByteCount(args[index]) ?? Int(result.initialMaxStreamData)) }
            case "--initial-max-streams-bidi":
                index += 1
                if index < args.count { result.initialMaxStreamsBidi = UInt64(Int(args[index]) ?? Int(result.initialMaxStreamsBidi)) }
            case "--udp-payload":
                index += 1
                if index < args.count { result.maxUDPPayloadSize = max(1200, Int(args[index]) ?? result.maxUDPPayloadSize) }
            case "--cert":
                index += 1
                if index < args.count { result.certPath = args[index] }
            case "--key":
                index += 1
                if index < args.count { result.keyPath = args[index] }
            case "--ca-cert":
                index += 1
                if index < args.count { result.caCertPath = args[index] }
            case "--server-name":
                index += 1
                if index < args.count { result.serverName = args[index] }
            case "--log-level":
                index += 1
                if index < args.count { result.logLevel = parseLogLevel(args[index]) ?? result.logLevel }
            default:
                break
            }
            index += 1
        }

        result.shards = min(result.shards, Int(UInt16.max) - Int(result.port) + 1)
        result.ports = min(result.ports, Int(UInt16.max) - Int(result.port) + 1)
        return result
    }
}

struct ClientConnection: Sendable {
    let endpoint: QUICEndpoint
    let quicConnection: any QUICConnectionProtocol
    let http3Connection: HTTP3Connection
    let authority: String
}

actor Metrics {
    private var requests: UInt64 = 0
    private var bytes: UInt64 = 0
    private var errors: UInt64 = 0
    private var latencyNanos: [UInt64] = []

    func record(bytes count: Int, latency: Duration) {
        requests += 1
        bytes += UInt64(max(0, count))
        latencyNanos.append(durationNanos(latency))
    }

    func recordError() {
        errors += 1
    }

    func snapshot() -> MetricsSnapshot {
        MetricsSnapshot(requests: requests, bytes: bytes, errors: errors, latencyNanos: latencyNanos)
    }
}

struct MetricsSnapshot: Sendable {
    let requests: UInt64
    let bytes: UInt64
    let errors: UInt64
    let latencyNanos: [UInt64]
}

@main
struct HTTP3Benchmark {
    static func main() async {
        let arguments = Arguments.parse()
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = arguments.logLevel
            return handler
        }

        do {
            switch arguments.mode {
            case .server:
                try await runServer(arguments)
            case .client:
                try await runClient(arguments)
            case .help:
                printHelp()
            }
        } catch {
            print("fatal: \(error)")
            exit(1)
        }
    }
}

func runServer(_ arguments: Arguments) async throws {
    print("HTTP3Benchmark server")
    print("  bind:             \(arguments.host):\(arguments.port)")
    print("  shards:           \(arguments.shards) port(s) \(arguments.port)..<\(Int(arguments.port) + arguments.shards)")
    print("  socket buffers:   \(formatBytes(arguments.socketBufferSize))")
    print("  flow control:     maxData=\(formatBytes(Int(arguments.initialMaxData))) stream=\(formatBytes(Int(arguments.initialMaxStreamData)))")
    print("  udp payload:      \(arguments.maxUDPPayloadSize) bytes")
    print("  routes:           GET /ping, GET /download, POST /upload")
    print("")

    let servers = (0..<arguments.shards).map { shard -> (HTTP3Server, UInt16) in
        let port = UInt16(Int(arguments.port) + shard)
        let server = HTTP3Server(options: serverOptions(arguments, port: port))
        return (server, port)
    }

    for (server, _) in servers {
        let router = benchmarkRouter(defaultBytes: arguments.bytesPerRequest, chunkSize: arguments.chunkSize)
        await server.onRequest(router.handler)
    }

    try await withThrowingTaskGroup(of: Void.self) { group in
        for (server, port) in servers {
            group.addTask {
                print("listening on \(arguments.host):\(port)")
                try await server.listen()
            }
        }
        try await group.waitForAll()
    }
}

func runClient(_ arguments: Arguments) async throws {
    print("HTTP3Benchmark client")
    print("  target:           \(arguments.host):\(arguments.port)")
    print("  ports:            \(arguments.ports) port(s) \(arguments.port)..<\(Int(arguments.port) + arguments.ports)")
    print("  workload:         \(arguments.workload.rawValue)")
    print("  duration:         \(arguments.durationSeconds)s")
    let clientConnectionCount = effectiveClientConnectionCount(arguments)

    print("  connections:      \(clientConnectionCount)" + (clientConnectionCount == arguments.connections ? "" : " (raised from \(arguments.connections) to avoid sharing active request loops)"))
    print("  concurrency:      \(arguments.concurrency)")
    print("  bytes/request:    \(formatBytes(arguments.bytesPerRequest))")
    print("  chunk size:       \(formatBytes(arguments.chunkSize))")
    print("  socket buffers:   \(formatBytes(arguments.socketBufferSize))")
    if let caCertPath = arguments.caCertPath {
        print("  ca cert:          \(caCertPath)")
        print("  server name:      \(tlsServerName(arguments))")
    }
    print("  note:             each client connection owns a UDP socket/event loop; use --ports with server --shards for multi-core server load")
    print("")

    let metrics = Metrics()
    let connections = try await openClientConnections(arguments, count: clientConnectionCount)

    print("connected:         \(connections.count)")
    print("warming hammer...\n")

    let started = ContinuousClock.now
    let deadline = started + .seconds(arguments.durationSeconds)

    let workers = (0..<arguments.concurrency).map { workerID in
        let connection = connections[workerID % connections.count]
        return Task {
            do {
                try await runWorker(
                    id: workerID,
                    arguments: arguments,
                    connection: connection,
                    deadline: deadline,
                    metrics: metrics
                )
            } catch is CancellationError {
            } catch {
                await metrics.recordError()
            }
        }
    }

    try? await Task.sleep(for: .seconds(arguments.durationSeconds))
    for worker in workers {
        worker.cancel()
    }

    let elapsed = started.duration(to: .now)
    let snapshot = await metrics.snapshot()
    printSummary(snapshot, elapsed: elapsed)

    for connection in connections {
        await connection.endpoint.stop()
    }
}

func effectiveClientConnectionCount(_ arguments: Arguments) -> Int {
    max(arguments.connections, arguments.concurrency)
}

func openClientConnections(_ arguments: Arguments, count: Int) async throws -> [ClientConnection] {
    try await withThrowingTaskGroup(of: ClientConnection.self) { group in
        for index in 0..<count {
            let port = UInt16(Int(arguments.port) + (index % arguments.ports))
            group.addTask {
                try await openClientConnection(arguments, port: port)
            }
        }

        var result: [ClientConnection] = []
        result.reserveCapacity(count)
        for try await connection in group {
            result.append(connection)
        }
        return result
    }
}

func openClientConnection(_ arguments: Arguments, port: UInt16) async throws -> ClientConnection {
    let quicConfig = clientQUICConfiguration(arguments)
    let endpoint = QUICEndpoint(configuration: quicConfig)
    let address = QUIC.SocketAddress(ipAddress: arguments.host, port: port)
    let quicConnection = try await endpoint.dial(address: address, timeout: .seconds(15))
    let http3Connection = HTTP3Connection(
        quicConnection: quicConnection,
        role: .client,
        settings: HTTP3Settings.literalOnly
    )
    try await http3Connection.initialize()
    try await http3Connection.waitForReady(timeout: .seconds(10))
    return ClientConnection(
        endpoint: endpoint,
        quicConnection: quicConnection,
        http3Connection: http3Connection,
        authority: "\(arguments.host):\(port)"
    )
}

func runWorker(
    id: Int,
    arguments: Arguments,
    connection: ClientConnection,
    deadline: ContinuousClock.Instant,
    metrics: Metrics
) async throws {
    var sequence = id
    while ContinuousClock.now < deadline {
        try Task.checkCancellation()
        let requestStart = ContinuousClock.now
        do {
            let workload = selectedWorkload(arguments.workload, sequence: sequence)
            let bytes = try await runOneRequest(
                workload: workload,
                arguments: arguments,
                connection: connection.http3Connection,
                authority: connection.authority,
                sequence: sequence
            )
            await metrics.record(bytes: bytes, latency: requestStart.duration(to: .now))
        } catch {
            await metrics.recordError()
        }
        sequence &+= arguments.concurrency
    }
}

func runOneRequest(
    workload: Arguments.Workload,
    arguments: Arguments,
    connection: HTTP3Connection,
    authority: String,
    sequence: Int
) async throws -> Int {
    switch workload {
    case .ping:
        let response = try await connection.sendRequest(HTTP3Request(
            method: .get,
            scheme: "https",
            authority: authority,
            path: "/ping"
        ))
        return try await consume(response)

    case .download:
        let response = try await connection.sendRequest(HTTP3Request(
            method: .get,
            scheme: "https",
            authority: authority,
            path: "/download",
            headers: [
                ("x-bench-bytes", "\(arguments.bytesPerRequest)"),
                ("x-bench-chunk-size", "\(arguments.chunkSize)"),
                ("x-bench-sequence", "\(sequence)")
            ]
        ))
        return try await consume(response)

    case .upload:
        let request = HTTP3Request(
            method: .post,
            scheme: "https",
            authority: authority,
            path: "/upload",
            headers: [
                ("content-type", "application/octet-stream"),
                ("x-bench-bytes", "\(arguments.bytesPerRequest)"),
                ("x-bench-sequence", "\(sequence)")
            ]
        )
        let response = try await connection.sendRequestWithBodyWriter(request) { writer in
            try await writeRepeatedBytes(
                totalBytes: arguments.bytesPerRequest,
                chunkSize: arguments.chunkSize,
                writer: writer
            )
        }
        _ = try await consume(response)
        return arguments.bytesPerRequest

    case .mixed:
        fatalError("mixed should be resolved before runOneRequest")
    }
}

func benchmarkRouter(defaultBytes: Int, chunkSize: Int) -> HTTP3Router {
    let router = HTTP3Router()
    let started = ContinuousClock.now

    router.get("/ping") { context, _ in
        let body = Data("ok".utf8)
        try await context.respond(
            status: 200,
            headers: [
                ("content-type", "text/plain"),
                ("cache-control", "no-store"),
                ("content-length", "\(body.count)")
            ],
            body
        )
    }

    router.get("/download") { context, _ in
        let totalBytes = headerInt(context.request.headers, "x-bench-bytes") ?? defaultBytes
        let requestedChunkSize = headerInt(context.request.headers, "x-bench-chunk-size") ?? chunkSize
        let chunk = makeChunk(size: max(1, requestedChunkSize))
        try await context.respond(
            status: 200,
            headers: [
                ("content-type", "application/octet-stream"),
                ("cache-control", "no-store"),
                ("content-length", "\(totalBytes)")
            ]
        ) { writer in
            var remaining = totalBytes
            while remaining > 0 {
                let count = min(remaining, chunk.count)
                if count == chunk.count {
                    try await writer.write(chunk)
                } else {
                    try await writer.write(Data(chunk.prefix(count)))
                }
                remaining -= count
            }
        }
    }

    router.post("/upload") { context, _ in
        var received = 0
        for await chunk in context.body.stream() {
            received += chunk.count
        }
        let body = Data("{\"received\":\(received)}".utf8)
        try await context.respond(
            status: 200,
            headers: [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
                ("content-length", "\(body.count)"),
                ("x-bench-received", "\(received)")
            ],
            body
        )
    }

    router.get("/stats") { context, _ in
        let uptime = started.duration(to: .now)
        let body = Data("{\"uptime_seconds\":\(String(format: "%.3f", seconds(uptime)))}".utf8)
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json"), ("content-length", "\(body.count)")],
            body
        )
    }

    router.setNotFound { context, _ in
        let body = Data("not found".utf8)
        try await context.respond(
            status: 404,
            headers: [("content-type", "text/plain"), ("content-length", "\(body.count)")],
            body
        )
    }

    return router
}

func serverOptions(_ arguments: Arguments, port: UInt16) -> HTTP3ServerOptions {
    var options: HTTP3ServerOptions
    if let certPath = arguments.certPath, let keyPath = arguments.keyPath {
        options = HTTP3ServerOptions(
            host: arguments.host,
            port: port,
            certificatePath: certPath,
            privateKeyPath: keyPath,
            verifyPeer: false,
            alpn: [h3ALPN],
            maxConnections: 100_000,
            maxIdleTimeout: .seconds(120)
        )
    } else {
        options = HTTP3ServerOptions(
            host: arguments.host,
            port: port,
            signingKey: SigningKey.generateP256(),
            certificateChain: [Data([0x30, 0x82, 0x01, 0x00])],
            verifyPeer: false,
            alpn: [h3ALPN],
            maxConnections: 100_000,
            maxIdleTimeout: .seconds(120),
            developmentMode: true
        )
    }
    options.initialMaxData = arguments.initialMaxData
    options.initialMaxStreamDataBidiLocal = arguments.initialMaxStreamData
    options.initialMaxStreamDataBidiRemote = arguments.initialMaxStreamData
    options.initialMaxStreamDataUni = arguments.initialMaxStreamData
    options.initialMaxStreamsBidi = arguments.initialMaxStreamsBidi
    options.initialMaxStreamsUni = arguments.initialMaxStreamsBidi
    options.socketConfiguration = SocketConfiguration(
        receiveBufferSize: arguments.socketBufferSize,
        sendBufferSize: arguments.socketBufferSize,
        maxDatagramSize: 65_507,
        enableECN: false,
        enableDF: true
    )
    return options
}

func clientQUICConfiguration(_ arguments: Arguments) -> QUICConfiguration {
    var mutableTLSConfig = TLSConfiguration.client(serverName: tlsServerName(arguments), alpnProtocols: [h3ALPN])
    if let caCertPath = arguments.caCertPath {
        try? mutableTLSConfig.loadTrustedCAs(fromPEMFile: caCertPath)
        mutableTLSConfig.verifyPeer = true
        mutableTLSConfig.allowSelfSigned = false
    } else {
        mutableTLSConfig.verifyPeer = false
        mutableTLSConfig.allowSelfSigned = true
    }
    let tlsConfig = mutableTLSConfig

    var config: QUICConfiguration
    if arguments.caCertPath == nil {
        config = QUICConfiguration.development { TLS13Handler(configuration: tlsConfig) }
    } else {
        config = QUICConfiguration.production { TLS13Handler(configuration: tlsConfig) }
    }
    config.alpn = [h3ALPN]
    config.maxIdleTimeout = .seconds(120)
    config.maxUDPPayloadSize = arguments.maxUDPPayloadSize
    config.initialMaxData = arguments.initialMaxData
    config.initialMaxStreamDataBidiLocal = arguments.initialMaxStreamData
    config.initialMaxStreamDataBidiRemote = arguments.initialMaxStreamData
    config.initialMaxStreamDataUni = arguments.initialMaxStreamData
    config.initialMaxStreamsBidi = arguments.initialMaxStreamsBidi
    config.initialMaxStreamsUni = arguments.initialMaxStreamsBidi
    config.socketConfiguration = SocketConfiguration(
        receiveBufferSize: arguments.socketBufferSize,
        sendBufferSize: arguments.socketBufferSize,
        maxDatagramSize: 65_507,
        enableECN: false,
        enableDF: true
    )
    return config
}

func tlsServerName(_ arguments: Arguments) -> String {
    arguments.serverName ?? arguments.host
}

func consume(_ response: consuming HTTP3Response) async throws -> Int {
    let status = response.status
    let expectedBytes = headerInt(response.headers, "content-length")
    guard status >= 200 && status < 300 else {
        _ = try await response.body().data(maxBytes: 1024 * 1024)
        throw HTTP3Error(code: .internalError, reason: "unexpected status \(status)")
    }

    var total = 0
    for await chunk in response.body().stream() {
        total += chunk.count
        if let expectedBytes, total >= expectedBytes {
            break
        }
    }
    return total
}

func writeRepeatedBytes(totalBytes: Int, chunkSize: Int, writer: HTTP3BodyWriter) async throws {
    let chunk = makeChunk(size: max(1, chunkSize))
    var remaining = totalBytes
    while remaining > 0 {
        let count = min(remaining, chunk.count)
        if count == chunk.count {
            try await writer.write(chunk)
        } else {
            try await writer.write(Data(chunk.prefix(count)))
        }
        remaining -= count
    }
}

func makeChunk(size: Int) -> Data {
    var data = Data(count: size)
    data.withUnsafeMutableBytes { rawBuffer in
        guard let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return }
        for index in 0..<size {
            bytes[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 17)
        }
    }
    return data
}

func selectedWorkload(_ workload: Arguments.Workload, sequence: Int) -> Arguments.Workload {
    if workload != .mixed { return workload }
    switch sequence % 10 {
    case 0, 1:
        return .upload
    case 2:
        return .ping
    default:
        return .download
    }
}

func headerInt(_ headers: [(String, String)], _ name: String) -> Int? {
    headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }.flatMap { Int($0.1) }
}

func durationNanos(_ duration: Duration) -> UInt64 {
    let components = duration.components
    let seconds = UInt64(max(0, components.seconds))
    let attos = UInt64(max(0, components.attoseconds))
    return seconds * 1_000_000_000 + attos / 1_000_000_000
}

func seconds(_ duration: Duration) -> Double {
    let nanos = durationNanos(duration)
    return Double(nanos) / 1_000_000_000.0
}

func printSummary(_ snapshot: MetricsSnapshot, elapsed: Duration) {
    let elapsedSeconds = max(seconds(elapsed), 0.000_001)
    let throughput = Double(snapshot.bytes) / elapsedSeconds
    let rps = Double(snapshot.requests) / elapsedSeconds
    let sorted = snapshot.latencyNanos.sorted()

    print("\nresults")
    print("  elapsed:          \(String(format: "%.3f", elapsedSeconds))s")
    print("  requests:         \(snapshot.requests)")
    print("  errors:           \(snapshot.errors)")
    print("  transferred:      \(formatBytes(Int(snapshot.bytes)))")
    print("  throughput:       \(formatBytesPerSecond(throughput)) (\(formatBitsPerSecond(throughput)))")
    print("  request rate:     \(String(format: "%.1f", rps)) req/s")
    if !sorted.isEmpty {
        print("  latency avg:      \(formatMillis(Double(sorted.reduce(0, +)) / Double(sorted.count)))")
        print("  latency p50:      \(formatMillis(percentile(sorted, 0.50)))")
        print("  latency p90:      \(formatMillis(percentile(sorted, 0.90)))")
        print("  latency p99:      \(formatMillis(percentile(sorted, 0.99)))")
    }
}

func percentile(_ sorted: [UInt64], _ fraction: Double) -> Double {
    guard !sorted.isEmpty else { return 0 }
    let index = min(sorted.count - 1, max(0, Int(Double(sorted.count - 1) * fraction)))
    return Double(sorted[index])
}

func formatMillis(_ nanos: Double) -> String {
    String(format: "%.3f ms", nanos / 1_000_000.0)
}

func formatBytes(_ bytes: Int) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"]
    var value = Double(bytes)
    var unit = 0
    while value >= 1024 && unit < units.count - 1 {
        value /= 1024
        unit += 1
    }
    return String(format: "%.2f %@", value, units[unit])
}

func formatBytesPerSecond(_ bytesPerSecond: Double) -> String {
    let units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    var value = bytesPerSecond
    var unit = 0
    while value >= 1024 && unit < units.count - 1 {
        value /= 1024
        unit += 1
    }
    return String(format: "%.2f %@", value, units[unit])
}

func formatBitsPerSecond(_ bytesPerSecond: Double) -> String {
    let bits = bytesPerSecond * 8
    let units = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"]
    var value = bits
    var unit = 0
    while value >= 1000 && unit < units.count - 1 {
        value /= 1000
        unit += 1
    }
    return String(format: "%.2f %@", value, units[unit])
}

func parseByteCount(_ raw: String) -> Int? {
    let lower = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let multipliers: [(String, Int)] = [
        ("gib", 1024 * 1024 * 1024), ("gb", 1000 * 1000 * 1000), ("g", 1024 * 1024 * 1024),
        ("mib", 1024 * 1024), ("mb", 1000 * 1000), ("m", 1024 * 1024),
        ("kib", 1024), ("kb", 1000), ("k", 1024),
        ("b", 1)
    ]
    for (suffix, multiplier) in multipliers where lower.hasSuffix(suffix) {
        let number = lower.dropLast(suffix.count)
        guard let value = Double(number) else { return nil }
        return Int(value * Double(multiplier))
    }
    return Int(lower)
}

func parseLogLevel(_ raw: String) -> Logger.Level? {
    switch raw.lowercased() {
    case "trace": return .trace
    case "debug": return .debug
    case "info": return .info
    case "notice": return .notice
    case "warning": return .warning
    case "error": return .error
    case "critical": return .critical
    default: return nil
    }
}

func printHelp() {
    print("""
    HTTP3Benchmark

    USAGE:
      swift run -c release HTTP3Benchmark server [options]
      swift run -c release HTTP3Benchmark client [options]

    SERVER OPTIONS:
      --host <addr>                       Bind host (default: \(defaultHost))
      --port <port>                       First UDP port (default: \(defaultPort))
      --shards <n>                        Start n server sockets on sequential ports
      --bytes <n|nK|nM|nG>                Default /download response size
      --chunk-size <n|nK|nM>              Streaming chunk size
      --socket-buffer <n|nM>              SO_RCVBUF/SO_SNDBUF request
      --initial-max-data <n|nM|nG>        Connection receive flow-control window
      --initial-max-stream-data <n|nM>    Per-stream receive flow-control window
      --udp-payload <bytes>               QUIC max UDP payload size
      --cert <path> --key <path>          Use real TLS cert/key

    CLIENT OPTIONS:
      --host <addr>                       Server host
      --port <port>                       First server UDP port
      --ports <n>                         Spread connections over sequential ports
      --workload download|upload|ping|mixed
      --duration <seconds>                Benchmark duration
      --connections <n>                   HTTP/3 connections to open
      --concurrency <n>                   Concurrent request loops
      --bytes <n|nK|nM|nG>                Payload bytes per request
      --chunk-size <n|nK|nM>              Upload/download chunk size
      --ca-cert <path>                    Verify server cert with CA
    --server-name <dns-or-ip>           TLS SNI/verification name (default: --host)

    EXAMPLES:
    swift run -c release HTTP3Benchmark server --host 0.0.0.0 --port 9443 --shards 12 --socket-buffer 32M --cert certs/localhost.crt --key certs/localhost.key
    swift run -c release HTTP3Benchmark client --host 192.168.1.10 --server-name 192.168.1.10 --ca-cert certs/localCA.crt --port 9443 --ports 12 --connections 48 --concurrency 48 --duration 60 --bytes 64K
      swift run -c release HTTP3Benchmark client --workload upload --connections 48 --concurrency 384 --bytes 4M

    MULTI-CORE NOTE:
      The current UDP socket path uses one NIO event-loop thread per socket when
      it creates its own transport. Use server --shards N plus client --ports N
      to create multiple sockets/event loops and make CPU scaling visible.
    """)
}
