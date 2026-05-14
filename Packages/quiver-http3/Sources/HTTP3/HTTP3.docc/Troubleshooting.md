# HTTP/3 Troubleshooting

Use this page to isolate and debug common runtime and interoperability issues in `HTTP3`.

## Quick Triage Checklist

1. Confirm transport reachability (UDP port, firewall, NAT behavior).
2. Verify certificate and TLS settings match client/server expectations.
3. Check ALPN and protocol negotiation.
4. Validate HTTP/3 SETTINGS exchange and control stream behavior.
5. Inspect stream lifecycle (open/write/close) and flow-control backpressure.
6. Capture logs for frame parsing, stream IDs, and connection shutdown reasons.

## Common Symptoms

### Connection Fails Before First Request

Possible causes:
- TLS certificate validation failure.
- ALPN mismatch.
- QUIC transport handshake/config mismatch.

What to inspect:
- Server bind address and port.
- Certificate chain, SAN, and host mapping.
- Client endpoint configuration and trust settings.

### Requests Stall or Timeout

Possible causes:
- Stream not fully closed on write side.
- Missing response headers/body finalization.
- Flow-control limits reached.

What to inspect:
- Request stream open/close sequence.
- Per-stream and connection-level window sizes.
- Whether read/write loops are blocked by awaiting unavailable data.

### Headers/Frames Decoding Errors

Possible causes:
- Malformed frame payloads.
- Invalid ordering on control streams.
- QPACK encode/decode mismatch.

What to inspect:
- Frame type and length parsing.
- Settings frame presence and ordering.
- Header block encoder/decoder compatibility.

### WebTransport Session Setup Fails

Possible causes:
- Extended CONNECT request mismatch.
- Missing/invalid response status.
- Session stream state invalid after acceptance.

What to inspect:
- CONNECT request pseudo-headers and authority/path.
- Server acceptance/rejection path.
- Session startup order and stream ownership.

## Logging Recommendations

Prioritize logs at:
- Connection establishment/teardown
- SETTINGS exchange
- Request stream creation and closure
- Frame codec errors with stream ID and frame type
- WebTransport session accept/reject path

Include:
- Connection identifier
- Stream ID
- Frame type
- Error code/reason
- Local/remote endpoint info

## Next Steps

- Add reproducible minimal cases for each failure mode.
- Add targeted integration tests for failing paths.
- Correlate application logs with protocol-level traces.

## Related Articles

- <doc:GettingStarted>
- <doc:ServerGuide>
- <doc:ClientGuide>
- <doc:WebTransportGuide>
- <doc:Architecture>