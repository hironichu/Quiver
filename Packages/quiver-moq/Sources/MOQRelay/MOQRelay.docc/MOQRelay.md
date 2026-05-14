# ``MOQRelay``

@Metadata {
  @DisplayName("MOQRelay")
}

A relay module for Media over QUIC (MoQ) flows, built on top of `MOQCore` and QUIC transport primitives.

## Overview

`MOQRelay` provides relay-oriented components to receive, route, and forward MoQ objects and tracks between publishers and subscribers.

Use this module when you need:

- Fan-out distribution of tracks to multiple subscribers
- Relay-side session orchestration
- Integration between MoQ core abstractions and transport/runtime concerns

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:Architecture>
- <doc:RelayOperationModel>

### Core APIs

- ``MOQRelay``

### Error Handling and Diagnostics

- <doc:ErrorsAndDiagnostics>
- <doc:OperationalGuidelines>

### Performance and Scaling

- <doc:Performance>
- <doc:BackpressureAndFlowControl>

## See Also

- [Media over QUIC draft](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
- [RFC 9000: QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)