# Technical Operations Plan: MTU-Aware Packet Generation

## Status: PENDING APPROVAL

---

## Problem Statement

`generateOutboundPackets()` produces exactly ONE QUIC packet per encryption level.
Two concurrent callers (`outboundSendLoop` and `packetReceiveLoop`) interleave frame
queue operations, resulting in packets that exceed `maxDatagramSize`. The encoder
throws `packetTooLarge`, frames are lost permanently, and stream data is corrupted.

Observed errors:
- `packetTooLarge(size: 2379, maxSize: 1200)` -- HTTP/3 server, POST echo
- `packetTooLarge(size: 2875, maxSize: 1452)` -- Benchmark client, bulk upload

---

## Root Causes

| ID | Cause | Location | Severity |
|----|-------|----------|----------|
| RC1 | Race: send loop + receive loop both call `generateOutboundPackets()` concurrently; non-atomic queue ops allow frame interleaving | `QUICConnectionHandler.getOutboundPackets()` L274-355 | Critical |
| RC2 | Single packet per level: all frames crammed into one packet regardless of total size | `ManagedConnection.generateOutboundPackets()` L887-967 | Critical |
| RC3 | Flow-control frames added after budget computation | `QUICConnectionHandler.getOutboundPackets()` L340-344 | Minor |
| RC4 | Frames lost on encoding failure: queue already drained when `packetTooLarge` throws | `ManagedConnection.generateOutboundPackets()` L898 drain vs L959 throw | Data loss |

---

## Affected Files

### Primary (must modify)

| File | Symbol | Change |
|------|--------|--------|
| `Sources/QUIC/ManagedConnection.swift` | `generateOutboundPackets()` L887-967 | Rewrite: multi-packet builder with MTU splitting |
| `Sources/QUIC/ManagedConnection.swift` | Property declarations ~L35 | Add `packetGenerationLock: Mutex<Void>` |
| `Sources/QUICConnection/QUICConnectionHandler.swift` | `getOutboundPackets()` L274-355 | Rewrite: atomic frame collection, budget includes flow-control |
| `Sources/QUICConnection/QUICConnectionHandler.swift` | `queueCryptoData()` L365-371 | Fix: subtract packet overhead from maxFrameSize |

### Secondary (may need minor touch)

| File | Symbol | Change |
|------|--------|--------|
| `Sources/QUIC/QUICEndpoint+IOLoop.swift` | `outboundSendLoop()` L177-260 | Defensive: log if packetTooLarge still occurs post-fix |
| `Sources/QUIC/QUICEndpoint+IOLoop.swift` | `packetReceiveLoop()` L141-162 | No change expected; benefits from serialization |
| `Sources/QUICConnection/FrameProcessingResult.swift` | `OutboundPacket` L68-84 | No change; struct is reused as-is |
| `Sources/QUICCore/Frame/FrameSize.swift` | all | No change; size calculations are correct |
| `Sources/QUICCore/Packet/PacketCodec.swift` | `encodeShortHeaderPacket()` L252-310, `encodeLongHeaderPacket()` L161-240 | No change; the guard is correct, callers must respect it |

### Not modified

| File | Reason |
|------|--------|
| `Sources/QUICStream/DataStream.swift` `generateFrames()` L416-510 | Stream frame budget logic is correct |
| `Sources/QUICStream/StreamManager.swift` `generateStreamFrames()` L498-550 | Budget tracking is correct |
| `Sources/QUIC/PacketProcessor.swift` | Passthrough to PacketCodec; no logic change |

---

## Execution Plan

### Phase 1: Serialize `generateOutboundPackets()` (fixes RC1)

**File:** `Sources/QUIC/ManagedConnection.swift`

**Step 1.1:** Add serialization lock to `ManagedConnection` properties (~L35).

```
private let packetGenerationLock = Mutex(())
```

**Step 1.2:** Wrap the ENTIRE body of `generateOutboundPackets()` in `packetGenerationLock.withLock { }`.

This guarantees that even if `outboundSendLoop` and `packetReceiveLoop` both call
`generateOutboundPackets()` concurrently, only one executes at a time. The second
caller sees a drained queue and generates only its own ACKs.

**Verification:** The `packetTooLarge` error caused by frame interleaving becomes
impossible -- each caller gets exactly the frames it generated.

**Risk:** Minor contention under load. Acceptable because packet generation is fast
(sub-microsecond for frame collection + encryption). The lock is NOT held across
any async operations.

---

### Phase 2: Atomic frame collection in `getOutboundPackets()` (reinforces RC1, fixes RC3)

**File:** `Sources/QUICConnection/QUICConnectionHandler.swift`

**Step 2.1:** Rewrite `getOutboundPackets()` to collect frames locally instead of
routing through `outboundQueue` with multiple lock/unlock cycles.

Current flow (6 separate lock acquisitions on `outboundQueue`):
```
1. queueFrame(ACK)           -- lock, append, unlock
2. outboundQueue.withLock    -- lock, compute budget, unlock
3. queueFrame(STREAM) x N   -- lock, append, unlock (per frame)
4. queueFrame(FLOW_CTL) x N -- lock, append, unlock (per frame)
5. outboundQueue.withLock    -- lock, drain all, unlock
```

New flow (1 lock acquisition on `outboundQueue`):
```
1. outboundQueue.withLock { snapshot = $0; $0.removeAll() }   -- atomic drain
2. Generate ACK frames         -> local array (no queue touch)
3. Generate flow-control frames -> local array (no queue touch)
4. Compute budget from snapshot + ACK + flow-control sizes
5. Generate stream frames      -> local array (no queue touch)
6. Return snapshot + ACK + flow-control + stream frames
```

**Step 2.2:** The budget computation now includes flow-control frame sizes (fixes RC3):

```
let controlFrameBytes = ackFrames.reduce(0) { $0 + FrameSize.frame($1) }
                      + flowFrames.reduce(0) { $0 + FrameSize.frame($1) }
let externalFrameBytes = snapshot.filter { $0.level == .application }
                        .flatMap { $0.frames }.reduce(0) { $0 + FrameSize.frame($1) }
let streamBudget = max(0, maxDatagramSize - packetOverhead - controlFrameBytes - externalFrameBytes)
```

**Step 2.3:** The method signature remains `func getOutboundPackets() -> [OutboundPacket]`.
Return type is unchanged. The `OutboundPacket` struct wraps `[Frame]` + `EncryptionLevel`.
Callers (`generateOutboundPackets()`) are unaffected.

**Key detail:** External frames (HANDSHAKE_DONE, PATH_RESPONSE, CONNECTION_CLOSE, DATAGRAM)
that were queued via `queueFrame()` from other code paths are captured in the atomic
snapshot drain and included in the budget computation.

---

### Phase 3: Multi-packet builder in `generateOutboundPackets()` (fixes RC2, RC4)

**File:** `Sources/QUIC/ManagedConnection.swift`

**Step 3.1:** Replace the single-packet-per-level logic with a frame-packing loop.

Current logic (L920-965):
```
// Consolidate ALL frames into one dict entry per level
var framesByLevel: [EncryptionLevel: [Frame]] = [:]
for packet in outboundPackets {
    framesByLevel[packet.level, default: []].append(contentsOf: packet.frames)
}
// Build ONE packet per level
if let appFrames = framesByLevel[.application] {
    let encrypted = try encryptShortHeaderPacket(frames: appFrames, ...)
    result.append(encrypted)
}
```

New logic:
```
var framesByLevel: [EncryptionLevel: [Frame]] = [:]
for packet in outboundPackets {
    guard packetProcessor.hasKeys(for: packet.level) else { continue }
    framesByLevel[packet.level, default: []].append(contentsOf: packet.frames)
}

// For each level, pack frames into MTU-sized packets
for level in [EncryptionLevel.initial, .handshake, .application] {
    guard let frames = framesByLevel[level], !frames.isEmpty else { continue }
    let packets = try buildMTUPackets(frames: frames, level: level)
    result.append(contentsOf: packets)
}
```

**Step 3.2:** Implement `buildMTUPackets(frames:level:)` as a new private method:

```
private func buildMTUPackets(frames: [Frame], level: EncryptionLevel) throws -> [Data] {
    let overhead = packetOverhead(for: level)
    let maxPayload = packetProcessor.maxDatagramSize - overhead
    var result: [Data] = []
    var batch: [Frame] = []
    var batchSize = 0

    for frame in frames {
        let frameSize = FrameSize.frame(frame)

        // If single frame exceeds max payload, it must go alone
        // (will be caught by encoder's guard; logged as error)
        if frameSize > maxPayload && batch.isEmpty {
            batch.append(frame)
            batchSize += frameSize
            // Flush oversized frame alone -- encoder will throw,
            // but at least other frames are not lost
            result.append(try encryptAndFlush(batch, level: level))
            batch = []
            batchSize = 0
            continue
        }

        // Adding this frame would exceed MTU -- flush current batch
        if batchSize + frameSize > maxPayload && !batch.isEmpty {
            result.append(try encryptAndFlush(batch, level: level))
            batch = []
            batchSize = 0
        }

        batch.append(frame)
        batchSize += frameSize
    }

    // Flush remaining
    if !batch.isEmpty {
        result.append(try encryptAndFlush(batch, level: level))
    }

    return result
}
```

**Step 3.3:** Implement `packetOverhead(for:)`:

```
private func packetOverhead(for level: EncryptionLevel) -> Int {
    let (scid, dcid, version) = state.withLock { s in
        (s.sourceConnectionID, s.destinationConnectionID, handler.version)
    }
    switch level {
    case .initial, .handshake:
        // Long header: 1 (flags) + 4 (version) + 1+DCID + 1+SCID + token(initial) + 2(length) + 4(PN) + 16(AEAD)
        var size = 1 + 4 + 1 + dcid.length + 1 + scid.length + 2 + 4 + PacketConstants.aeadTagSize
        if level == .initial {
            size += 1  // token length varint (0 = 1 byte)
        }
        return size
    case .application:
        // Short header: 1 (flags) + DCID + 4(PN) + 16(AEAD)
        return 1 + dcid.length + 4 + PacketConstants.aeadTagSize
    }
}
```

**Step 3.4:** Implement `encryptAndFlush(_:level:)`:

```
private func encryptAndFlush(_ frames: [Frame], level: EncryptionLevel) throws -> Data {
    let pn = handler.getNextPacketNumber(for: level)
    let header = buildPacketHeader(for: level, packetNumber: pn)

    switch (level, header) {
    case (.initial, .long(let lh)):
        return try packetProcessor.encryptLongHeaderPacket(
            frames: frames, header: lh, packetNumber: pn, padToMinimum: true
        )
    case (.handshake, .long(let lh)):
        return try packetProcessor.encryptLongHeaderPacket(
            frames: frames, header: lh, packetNumber: pn, padToMinimum: false
        )
    case (.application, .short(let sh)):
        return try packetProcessor.encryptShortHeaderPacket(
            frames: frames, header: sh, packetNumber: pn
        )
    default:
        // Mismatched level/header -- should never happen
        throw PacketCodecError.invalidPacketFormat("Header type mismatch for level \(level)")
    }
}
```

**RC4 resolution:** With multi-packet splitting, the encoder's `packetTooLarge` guard
should never trigger for well-budgeted frames. If a single frame is inherently
oversized (e.g., an ACK with hundreds of ranges), it goes into its own packet and
fails alone -- other frames are preserved in subsequent packets.

---

### Phase 4: CRYPTO frame max size fix

**File:** `Sources/QUICConnection/QUICConnectionHandler.swift`

**Step 4.1:** In `queueCryptoData()` (L365-371), change:

```
// BEFORE:
let frames = cryptoStreamManager.createFrames(for: data, at: level, maxFrameSize: maxDatagramSize)

// AFTER -- subtract worst-case long header overhead so each frame fits in one packet:
let longHeaderOverhead = 1 + 4 + 1 + 20 + 1 + 20 + 1 + 2 + 4 + PacketConstants.aeadTagSize  // = 70
let maxCryptoPayload = max(64, maxDatagramSize - longHeaderOverhead)
let frames = cryptoStreamManager.createFrames(for: data, at: level, maxFrameSize: maxCryptoPayload)
```

This ensures each CRYPTO frame, when placed alone in a long-header packet, fits within MTU.
Phase 3's multi-packet builder handles the case where multiple small CRYPTO frames are
consolidated into fewer packets.

---

## Execution Order and Dependencies

```
Phase 1 (serialization lock)
   |
   v
Phase 2 (atomic frame collection)  -- depends on Phase 1 being in place
   |                                   so the new code path is not racy
   v
Phase 3 (multi-packet builder)     -- depends on Phase 2 returning correct
   |                                   frame lists
   v
Phase 4 (CRYPTO frame sizing)      -- independent, but logically last
```

Phases 1+2 can be done together in one commit.
Phase 3 replaces the code that Phase 1 wraps, so it must come after.
Phase 4 is a standalone fix.

---

## Validation Criteria

### Criterion 1: No `packetTooLarge` errors

Run HTTP/3 server, POST 1.05MB body via curl:
```
python3 -c "print('H'*1050000)" | curl -X POST -H 'Content-Type: application/json' \
  --http3 -ik https://localhost:4443/api/json --data-binary @-
```
Expected: Full JSON response received. No `packetTooLarge` warnings in server logs.

### Criterion 2: Benchmark completes without warnings

Run `BenchmarkServer` + `BenchmarkClient`.
Expected: All phases complete. No `packetTooLarge` or `Failed to send outbound packets` in either log.

### Criterion 3: Packet sizes within MTU

Add temporary trace logging in `encryptAndFlush`:
```
Self.logger.trace("Emitting \(level) packet: \(encrypted.count) bytes (\(frames.count) frames)")
```
Expected: All logged sizes <= `maxDatagramSize`.

### Criterion 4: Existing tests pass

```
swift test --filter QUICTests
swift test --filter QUICConnectionTests
swift test --filter QUICCoreTests
swift test --filter QUICStreamTests
swift test --filter HTTP3Tests
```

### Criterion 5: Large transfer throughput

After fix, the send loop should produce MULTIPLE packets per round (not just 1).
For 1.05MB response at MTU 1200: expect ~900 packets across ~900 send-loop rounds
(or fewer rounds if multiple packets per round from multi-packet builder).

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Lock contention on `packetGenerationLock` | Slight latency increase under very high concurrency | Lock is held only for CPU-bound work (no I/O, no async); sub-microsecond critical section |
| Increased packet count (multiple small packets instead of one large) | More UDP send calls | Unavoidable by RFC 9000 Section 14; can batch via sendmmsg later |
| Packet number consumption increases (each split packet uses a PN) | PN space exhaustion (theoretical) | PN space is 62-bit; not a practical concern |
| Initial packet padding: multi-packet might produce multiple padded Initials | Wasted bandwidth on Initial retransmit | Only the FIRST Initial needs padding; subsequent packets set `padToMinimum: false` |
| ACK frame larger than MTU (hundreds of ranges) | Single ACK frame cannot fit in any packet | Extremely rare; ACK frames should be coalesced before reaching this size; add defensive truncation if needed |

---

## Files Modified (Final Checklist)

- [ ] `Sources/QUIC/ManagedConnection.swift` -- Phase 1 (lock), Phase 3 (multi-packet builder)
- [ ] `Sources/QUICConnection/QUICConnectionHandler.swift` -- Phase 2 (atomic collection), Phase 4 (CRYPTO sizing)
- [ ] `Sources/QUIC/QUICEndpoint+IOLoop.swift` -- Optional: defensive logging improvement

**No other files require modification.**