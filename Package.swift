// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "Quiver",

    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],

    products: [
        // Main public API
        .library(
            name: "QUIC",
            targets: ["QUIC"]
        ),
        // Core types (no I/O dependencies)
        .library(
            name: "QUICCore",
            targets: ["QUICCore"]
        ),
        // QPACK header compression (RFC 9204)
        .library(
            name: "QPACK",
            targets: ["QPACK"]
        ),
        // HTTP/3 protocol (RFC 9114)
        .library(
            name: "HTTP3",
            targets: ["HTTP3"]
        ),
        // Example: QUIC Echo Server/Client
        .executable(
            name: "QUICEchoServer",
            targets: ["QUICEchoServer"]
        ),
        // Example: HTTP/3 Demo Server/Client
        .executable(
            name: "HTTP3Demo",
            targets: ["HTTP3Demo"]
        ),
        // Example: WebTransport Echo Server/Client
        .executable(
            name: "WebTransportDemo",
            targets: ["WebTransportDemo"]
        ),
    ],
    dependencies: [
        // UDP transport
        .package(url: "https://github.com/hironichu/swift-nio-udp", branch: "main"),

        // Cryptography
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.3"),
    ],
    targets: [
        // MARK: - Core Types (No I/O)

        .target(
            name: "QUICCore",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUICCore"
        ),

        // MARK: - Crypto Layer

        .target(
            name: "QUICCrypto",
            dependencies: [
                "QUICCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/QUICCrypto",
            exclude: ["TLS/TLS_SECURITY.md"]
        ),

        // MARK: - Connection Management

        .target(
            name: "QUICConnection",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICStream",
                "QUICRecovery",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUICConnection"
        ),

        // MARK: - Stream Management

        .target(
            name: "QUICStream",
            dependencies: [
                "QUICCore",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUICStream"
        ),

        // MARK: - Loss Detection & Congestion Control

        .target(
            name: "QUICRecovery",
            dependencies: [
                "QUICCore",
            ],
            path: "Sources/QUICRecovery"
        ),

        // MARK: - UDP Transport Integration

        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
            ],
            path: "Sources/QUICTransport"
        ),

        // MARK: - Main Public API

        .target(
            name: "QUIC",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICStream",
                "QUICRecovery",
                "QUICTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUIC"
        ),

        // MARK: - QPACK (Header Compression, RFC 9204)

        .target(
            name: "QPACK",
            dependencies: [],
            path: "Sources/QPACK"
        ),

        // MARK: - HTTP/3 (RFC 9114)

        .target(
            name: "HTTP3",
            dependencies: [
                "QUIC",
                "QPACK",
                "QUICCore",
                "QUICStream",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/HTTP3"
        ),

        // MARK: - Test Support

        .target(
            name: "QuiverTestSupport",
            dependencies: [
                "QUICCore",
            ],
            path: "Tests/QuiverTestSupport"
        ),

        // MARK: - Tests

        .testTarget(
            name: "QUICCoreTests",
            dependencies: ["QUICCore"],
            path: "Tests/QUICCoreTests"
        ),

        .testTarget(
            name: "QUICCryptoTests",
            dependencies: ["QUICCrypto"],
            path: "Tests/QUICCryptoTests"
        ),

        .testTarget(
            name: "QUICRecoveryTests",
            dependencies: ["QUICRecovery", "QUICCore"],
            path: "Tests/QUICRecoveryTests"
        ),

        .testTarget(
            name: "QUICStreamTests",
            dependencies: ["QUICStream", "QUICCore"],
            path: "Tests/QUICStreamTests"
        ),

        .testTarget(
            name: "QUICTests",
            dependencies: [
                "QUIC",
                "QUICRecovery",
                "QUICTransport",
                "QuiverTestSupport",
            ],
            path: "Tests/QUICTests"
        ),

        .testTarget(
            name: "QPACKTests",
            dependencies: ["QPACK"],
            path: "Tests/QPACKTests"
        ),

        .testTarget(
            name: "HTTP3Tests",
            dependencies: [
                "HTTP3",
                "QUIC",
                "QPACK",
                "QUICCore",
                "QuiverTestSupport",
            ],
            path: "Tests/HTTP3Tests"
        ),

        // MARK: - Benchmarks (run separately with: swift test --filter QUICBenchmarks)

        .testTarget(
            name: "QUICBenchmarks",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
            ],
            path: "Tests/QUICBenchmarks"
        ),

        // MARK: - Examples

        .executableTarget(
            name: "QUICEchoServer",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "QUICTransport",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/QUICEchoServer"
        ),

        .executableTarget(
            name: "HTTP3Demo",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "QUICTransport",
                "HTTP3",
                "QPACK",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/HTTP3Demo"
        ),

        .executableTarget(
            name: "WebTransportDemo",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "QUICTransport",
                "HTTP3",
                "QPACK",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/WebTransportDemo"
        ),
    ]
)
