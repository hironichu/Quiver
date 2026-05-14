# ``WebTransport``

Client-facing WebTransport facade for Quiver.

## Overview

This package exposes Quiver's WebTransport APIs from the HTTP/3 implementation as a standalone Swift package product. The server-side session registry and stream/datagram routing remain implemented inside `HTTP3`, where they integrate with `HTTP3Connection`.

Use this package when you want to consume WebTransport APIs directly without depending on the root `Quiver` aggregate package.
