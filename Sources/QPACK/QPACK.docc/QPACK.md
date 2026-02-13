# ``QPACK``

A pure Swift implementation of QPACK (RFC 9204) for HTTP/3 header compression and decompression.

## Overview

`QPACK` provides core primitives for encoding and decoding HTTP field sections over HTTP/3, including static table usage, integer encoding, string encoding, and Huffman coding.

Use this module when you need:
- Header block encoding for HTTP/3 request/response headers.
- Header block decoding from peer endpoints.
- RFC-aligned QPACK integer and string primitives.
- Deterministic behavior suitable for protocol-level testing.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:Architecture>
- <doc:EncodingAndDecoding>
- <doc:ErrorHandling>

### Core Types

- ``QPACKEncoder``
- ``QPACKDecoder``
- ``QPACKStaticTable``
- ``HuffmanCodec``
- ``QPACKInteger``
- ``QPACKString``

### Validation

- <doc:ComplianceAndTesting>
- <doc:PerformanceNotes>

## See Also

- [RFC 9204: QPACK](https://www.rfc-editor.org/rfc/rfc9204)