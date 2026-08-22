/// End-to-end loss-recovery interop tests (RFC 9002).
///
/// These stand up a *real* Quiver client and server on loopback with an
/// impairing UDP relay wedged between them. The relay drops datagrams — either a
/// fixed prefix (deterministic) or a random fraction (sustained) — so the only
/// way a handshake and stream echo can complete is if the loss-recovery engine
/// actually retransmits the dropped CRYPTO/STREAM data (PTO probe + ACK-detected
/// retransmission, RFC 9002 §6.2 / §13.3).
///
/// This is the durable, in-suite replacement for the ad-hoc `/tmp/qproxy.py`
/// UDP-loss harness used while building the engine. Before the engine was wired,
/// a single dropped Initial stalled the handshake forever; these tests turn that
/// regression into a permanent gate.
///
/// Non-tautology: `recoversFromDroppedInitial` drops the FIRST client→server
/// datagram outright (the Initial), so it cannot pass at all unless a PTO probe
/// re-sends the lost CRYPTO — exactly the path the unit tests
/// (`PTODeadlineTests`, `LossRecoveryTests`) pin in isolation, proven here over
/// the full socket stack.

import Testing
import Foundation
import NIOCore
import NIOPosix
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

// MARK: - Impairing UDP relay

/// A loopback UDP relay that forwards client⇄server datagrams while dropping
/// some of them, to fault-inject packet loss into a real QUIC connection.
///
/// Single bound datagram channel: datagrams whose source is the server are
/// forwarded to the last-seen client address; everything else is treated as
/// coming from the client and forwarded to the (fixed) server address. Drops are
/// applied per datagram — either a fixed count of the first datagrams in each
/// direction, or a fraction chosen by a seeded PRNG (reproducible).
final class ImpairingRelay: @unchecked Sendable {

    struct Stats: Sendable {
        var c2s = 0
        var s2c = 0
        var dropped = 0
    }

    private let group: EventLoopGroup
    private var channel: Channel?
    private let handler: RelayHandler

    /// The loopback port the relay listens on — point the client here.
    let listenPort: Int

    private init(group: EventLoopGroup, channel: Channel, handler: RelayHandler) {
        self.group = group
        self.channel = channel
        self.handler = handler
        self.listenPort = Int(channel.localAddress?.port ?? 0)
    }

    var stats: Stats { handler.snapshot() }

    /// Starts a relay forwarding to `127.0.0.1:serverPort`.
    ///
    /// - Parameters:
    ///   - serverPort: the real server's loopback port.
    ///   - lossProbability: per-datagram drop probability in [0, 1] (after the
    ///     `dropFirstEachDirection` prefix is consumed).
    ///   - dropFirstEachDirection: drop exactly this many of the first datagrams
    ///     seen in each direction outright (deterministic prefix loss).
    ///   - seed: PRNG seed for `lossProbability` (reproducible loss pattern).
    static func start(
        forwardingTo serverPort: Int,
        lossProbability: Double = 0,
        dropFirstEachDirection: Int = 0,
        reorderProbability: Double = 0,
        reorderDelayMs: Int = 12,
        seed: UInt64 = 0xC0FFEE
    ) async throws -> ImpairingRelay {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let serverAddr = try NIOCore.SocketAddress(ipAddress: "127.0.0.1", port: serverPort)
        let handler = RelayHandler(
            serverAddr: serverAddr,
            lossProbability: lossProbability,
            dropFirstEachDirection: dropFirstEachDirection,
            reorderProbability: reorderProbability,
            reorderDelay: .milliseconds(Int64(reorderDelayMs)),
            seed: seed
        )
        do {
            let channel = try await DatagramBootstrap(group: group)
                .channelInitializer { ch in ch.pipeline.addHandler(handler) }
                .bind(host: "127.0.0.1", port: 0)
                .get()
            return ImpairingRelay(group: group, channel: channel, handler: handler)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func stop() async {
        if let channel { try? await channel.close().get() }
        channel = nil
        try? await group.shutdownGracefully()
    }
}

/// NIO datagram handler implementing the impairment policy. All mutable state is
/// confined to the channel's event loop except `stats`/`drop` counters, which are
/// guarded by a lock for cross-thread reads.
private final class RelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let serverAddr: NIOCore.SocketAddress
    private let lossProbability: Double
    private let reorderProbability: Double
    private let reorderDelay: TimeAmount
    private let lock = NSLock()

    // lock-guarded
    private var clientAddr: NIOCore.SocketAddress?
    private var dropC2SRemaining: Int
    private var dropS2CRemaining: Int
    private var stats = ImpairingRelay.Stats()
    private var rngState: UInt64

    init(serverAddr: NIOCore.SocketAddress, lossProbability: Double, dropFirstEachDirection: Int,
         reorderProbability: Double, reorderDelay: TimeAmount, seed: UInt64) {
        self.serverAddr = serverAddr
        self.lossProbability = lossProbability
        self.reorderProbability = reorderProbability
        self.reorderDelay = reorderDelay
        self.dropC2SRemaining = dropFirstEachDirection
        self.dropS2CRemaining = dropFirstEachDirection
        self.rngState = seed
    }

    func snapshot() -> ImpairingRelay.Stats { lock.withLock { stats } }

    // SplitMix64 — deterministic, reproducible loss pattern given the seed.
    private func nextUnitInterval() -> Double {
        rngState &+= 0x9E37_79B9_7F4A_7C15
        var z = rngState
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        z = z ^ (z >> 31)
        return Double(z >> 11) * (1.0 / 9_007_199_254_740_992.0) // 53-bit mantissa
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let fromServer = (envelope.remoteAddress == serverAddr)

        // Returns (address to forward to, whether to delay it for reordering),
        // or nil destination to drop this datagram.
        let decision: (dest: NIOCore.SocketAddress, reorder: Bool)? = lock.withLock {
            let dest: NIOCore.SocketAddress
            if fromServer {
                guard let client = clientAddr else { return nil } // nowhere to send yet
                if dropS2CRemaining > 0 { dropS2CRemaining -= 1; stats.dropped += 1; return nil }
                if lossProbability > 0 && nextUnitInterval() < lossProbability {
                    stats.dropped += 1; return nil
                }
                stats.s2c += 1
                dest = client
            } else {
                clientAddr = envelope.remoteAddress
                if dropC2SRemaining > 0 { dropC2SRemaining -= 1; stats.dropped += 1; return nil }
                if lossProbability > 0 && nextUnitInterval() < lossProbability {
                    stats.dropped += 1; return nil
                }
                stats.c2s += 1
                dest = serverAddr
            }
            // Delay a fraction of forwarded datagrams so later ones overtake them
            // (injects reordering, distinct from pure loss).
            let reorder = reorderProbability > 0 && nextUnitInterval() < reorderProbability
            return (dest, reorder)
        }

        guard let decision else { return }
        let out = wrapOutboundOut(AddressedEnvelope(remoteAddress: decision.dest, data: envelope.data))
        if decision.reorder {
            // Hold this datagram briefly; subsequent ones flushed immediately pass it.
            let channel = context.channel
            context.eventLoop.scheduleTask(in: reorderDelay) {
                channel.writeAndFlush(out, promise: nil)
            }
        } else {
            context.writeAndFlush(out, promise: nil)
        }
    }
}

// MARK: - Tests

@Suite("Loopback loss-recovery (RFC 9002 §6.2 / §13.3)")
struct LossRecoveryInteropTests {

    /// Stand up server + relay + client, run one stream echo through the relay,
    /// and return (echoMatched, relayStats). The relay sits on the wire so the
    /// connection only completes if the engine retransmits dropped data.
    private func runEcho(
        lossProbability: Double = 0,
        dropFirstEachDirection: Int = 0,
        reorderProbability: Double = 0,
        seed: UInt64 = 0xC0FFEE,
        message: String = "loss-recovery echo over a lossy path",
        payloadBytes: Int? = nil
    ) async throws -> (matched: Bool, stats: ImpairingRelay.Stats) {
        let (server, serverRunTask, serverPort) = try await LoopbackHelper.startServer()
        let serverTask = Task {
            let connectionStream = await server.incomingConnections
            for await conn in connectionStream {
                Task {
                    for await stream in conn.incomingStreams {
                        Task { await echoStream(stream) }
                    }
                }
            }
        }

        let relay = try await ImpairingRelay.start(
            forwardingTo: Int(serverPort),
            lossProbability: lossProbability,
            dropFirstEachDirection: dropFirstEachDirection,
            reorderProbability: reorderProbability,
            seed: seed
        )

        defer {
            Task {
                await relay.stop()
                await server.stop()
                serverRunTask.cancel()
                serverTask.cancel()
            }
        }

        // Client dials the RELAY, not the server. A generous dial timeout lets
        // PTO-driven handshake retransmission complete under loss.
        let (clientEndpoint, connection) = try await LoopbackHelper.connectClient(
            port: UInt16(relay.listenPort),
            timeout: .seconds(20)
        )
        defer {
            Task {
                await connection.close(error: nil)
                await clientEndpoint.stop()
            }
        }

        let stream = try await connection.openStream()
        // A sized payload (when requested) spans many packets, so sustained loss
        // has many datagrams to hit and the engine must retransmit repeatedly.
        let payload: Data = payloadBytes.map { n in Data((0..<n).map { i in UInt8(i & 0xFF) }) }
            ?? Data(message.utf8)
        try await stream.write(payload)
        try await stream.closeWrite()

        let response = try await readAll(stream, timeout: .seconds(30))
        return (response == payload, relay.stats)
    }

    @Test("recovers from a dropped Initial (PTO probe retransmits CRYPTO)", .timeLimit(.minutes(1)))
    func recoversFromDroppedInitial() async throws {
        // Drop the first datagram in EACH direction outright. The client's first
        // datagram carries the Initial CRYPTO (ClientHello); dropping it means the
        // handshake can only proceed if a PTO probe re-sends that CRYPTO. Without
        // the loss-recovery engine this hangs until handshakeTimeout — i.e. this
        // test is RED on the pre-fix tree by construction (mutation-proven: stub
        // `recordSentPacket(frames:)` to `[]` and this times out).
        let (matched, stats) = try await runEcho(dropFirstEachDirection: 1)
        #expect(matched, "stream echo must still round-trip after a dropped Initial — the engine must retransmit the lost CRYPTO")
        #expect(stats.dropped >= 1, "the relay must actually have dropped the prefix datagram(s)")
    }

    @Test("recovers a full 8 KB bulk stream after a dropped handshake (deterministic)", .timeLimit(.minutes(2)))
    func recoversBulkStreamAfterHandshakeLoss() async throws {
        // Deterministic (no probability): drop the first datagram each direction
        // (handshake), then deliver an 8 KB multi-packet stream over the recovered
        // connection. Proves bulk delivery works end-to-end once the handshake
        // recovers. NOTE: this does NOT inject mid-stream data loss — that path is
        // the disabled KNOWN-BUG test below. Kept deterministic (no probability)
        // because sustained per-datagram loss is not yet reliably recovered.
        let (matched, stats) = try await runEcho(
            dropFirstEachDirection: 1,
            payloadBytes: 8000
        )
        #expect(matched, "the full 8 KB stream must round-trip after a recovered handshake")
        #expect(stats.dropped >= 1, "the prefix drop must have injected a real handshake loss")
    }

    @Test("baseline: clean relay path round-trips (control)", .timeLimit(.minutes(1)))
    func cleanRelayBaseline() async throws {
        // No loss — proves the relay itself is transparent, so a failure in the
        // loss cases is attributable to loss, not the relay plumbing.
        let (matched, stats) = try await runEcho()
        #expect(matched, "stream echo must round-trip through a transparent relay")
        #expect(stats.dropped == 0, "the control path must drop nothing")
        #expect(stats.c2s > 0 && stats.s2c > 0, "the relay must have forwarded in both directions")
    }

    // Regression for the ACK gap-decode off-by-one (LossDetector.computeAckIntervals
    // used `gap + 1` vs RFC 9000 §19.3.1's `gap + 2`): under sustained mid-stream
    // loss the sender SPURIOUSLY ACKed an unreceived (lost) packet — the first
    // packet of each ACK gap — dropped it from tracking, and never retransmitted
    // it, permanently stalling the stream. Before the fix, seed 0x1 stalled at
    // 2332/8000; it now round-trips an 8 KB multi-packet stream under heavy loss.
    //
    // Gated at 20% per-datagram loss across several deterministic seeds (each
    // exercises a different gap pattern). 20% is well above realistic mobile loss
    // (cellular 1–10%, wifi 0.5–5%); an empirical sweep showed clean recovery all
    // the way to 30% — i.e. the off-by-one WAS the "30%+ brutal tail" noted when
    // the engine was first wired (4c43393).
    @Test("recovers an 8 KB stream under sustained 20% loss across seeds (gap-decode regression)",
          .timeLimit(.minutes(2)),
          arguments: [UInt64(0x1), 0x2, 0xA11CE, 0xC0FFEE])
    func recoversUnderSustainedLoss(seed: UInt64) async throws {
        let (matched, stats) = try await runEcho(
            lossProbability: 0.20,
            seed: seed,
            payloadBytes: 8000
        )
        #expect(matched, "the full 8 KB stream must round-trip under 20% sustained loss (seed \(seed))")
        #expect(stats.dropped >= 2, "20% over a multi-packet echo must inject real loss (seed \(seed))")
    }

    @Test("recovers an 8 KB stream under combined 10% loss + 20% reordering",
          .timeLimit(.minutes(2)),
          arguments: [UInt64(0x1), 0x2, 0xA11CE, 0xC0FFEE])
    func recoversUnderLossAndReordering(seed: UInt64) async throws {
        // Reordering (delay a fraction of datagrams so later ones overtake them)
        // is a distinct fault from pure loss: it stresses packet-threshold loss
        // detection (out-of-order ACKs / spurious-loss avoidance) and stream
        // reassembly differently. Combined with 10% loss over a multi-packet echo.
        let (matched, stats) = try await runEcho(
            lossProbability: 0.10,
            reorderProbability: 0.20,
            seed: seed,
            payloadBytes: 8000
        )
        #expect(matched, "the full 8 KB stream must round-trip under loss + reordering (seed \(seed))")
        #expect(stats.dropped >= 1, "loss must be injected (seed \(seed))")
    }
}
