# ``MOQCore``

Media over QUIC core primitives for modeling sessions, tracks, and objects.

## Overview

`MOQCore` provides the protocol-level building blocks for Media over QUIC (MOQ) workflows in Quiver.  
Use this module to represent and coordinate media publication/subscription state independently from relay- or client-specific transport orchestration.

This page is a skeleton and should be expanded with:
- protocol compliance notes and supported draft/RFC scope
- end-to-end publish/subscribe lifecycle
- state machine and error semantics
- interoperability and backpressure behavior

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:Architecture>
- <doc:SessionLifecycle>
- <doc:ErrorHandling>

### Core Types

- ``MOQSession``
- ``MOQTrack``
- ``MOQObject``

### Integration

- <doc:WithMOQRelay>
- <doc:WithMOQClient>
- <doc:WithQUICAndHTTP3>

## See Also

- [Media over QUIC draft](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
- [RFC 9000: QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)
