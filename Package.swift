// swift-tools-version: 6.2

import PackageDescription

// When SWIFTCI_USE_LOCAL_DEPS is set (mirrors Apple's CI convention), resolve
// swift-nio and swift-nio-ssl from local sibling checkouts that contain the
// Windows-specific patches pending upstream PRs. In all other environments the
// published forks on hironichu/swift-nio and hironichu/swift-nio-ssl are used.
let useLocalDeps = Context.environment["SWIFTCI_USE_LOCAL_DEPS"] != nil

func nioDependencies() -> [Package.Dependency] {
    if useLocalDeps {
        return [
            .package(path: "../swift-nio"),
            .package(path: "../swift-nio-ssl"),
            .package(path: "../swift-system"),
        ]
    } else {
        return [
            // Fork of apple/swift-nio with Windows fixes (PR #3433).
            .package(url: "https://github.com/hironichu/swift-nio.git", branch: "pr-3433"),
            // Fork of apple/swift-nio-ssl with Windows support (PR #567).
            .package(url: "https://github.com/hironichu/swift-nio-ssl.git", branch: "pr-567-windows-support"),
            .package(url: "https://github.com/apple/swift-system.git", from: "1.6.4"),
        ]
    }
}

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
        // Auth extensions for HTTP/3 / Extended CONNECT
        .library(
            name: "QuiverAuth",
            targets: ["QuiverAuth"]
        ),
        // Media Over QUIC (MOQ)
        .library(
            name: "MOQCore",
            targets: ["MOQCore"]
        ),
        .library(
            name: "MOQRelay",
            targets: ["MOQRelay"]
        ),
        .library(
            name: "MOQClient",
            targets: ["MOQClient"]
        ),
    ],
    dependencies: nioDependencies() + [
        // Cryptography — 4.5.0+ depends on an unstable swift-asn1; cap below it.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.5.0"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),

        // JWT / JWK verification (cross-platform, maintained)
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.5.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.5.0"),
    ],
    targets: [
        // MARK: - Core Types (No I/O)

        .target(
            name: "QUICCore",
            dependencies: [
                .product(name: "Logging", package: "swift-log")
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

        // MARK: - UDP Transport (inlined from swift-nio-udp)

        .target(
            name: "NIOUDPTransport",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/NIOUDPTransport"
        ),

        // MARK: - Connection Management

        .target(
            name: "QUICConnection",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICStream",
                "QUICRecovery",
                "QUICTransport",
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
                "QUICCore"
            ],
            path: "Sources/QUICRecovery"
        ),

        // MARK: - UDP Transport Integration

        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
                "NIOUDPTransport",
                .product(name: "SystemPackage", package: "swift-system"),
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
                "QUICCrypto",
                "QUICStream",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/HTTP3"
        ),

        .target(
            name: "QuiverAuth",
            dependencies: [
                "HTTP3",
                "QUIC",
                "QUICCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            path: "Sources/QuiverAuth"
        ),

        // MARK: - MOQ Core

        .target(
            name: "MOQCore",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICStream",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQCore"
        ),

        // MARK: - MOQ Relay & Client

        .target(
            name: "MOQRelay",
            dependencies: [
                "MOQCore",
                "QUICCore",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQRelay"
        ),

        .target(
            name: "MOQClient",
            dependencies: [
                "MOQCore",
                "QUICCore",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQClient"
        ),

        // MARK: - Test Support

        .target(
            name: "QuiverTestSupport",
            dependencies: [
                "QUICCore"
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
            name: "MOQCoreTests",
            dependencies: ["MOQCore", "MOQRelay", "QUICCore"],
            path: "Tests/MOQCoreTests"
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
            name: "QUICConnectionTests",
            dependencies: [
                "QUICConnection",
                "QUICCore",
                "QUIC",
                "QuiverTestSupport",
            ],
            path: "Tests/QUICConnectionTests"
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

        .testTarget(
            name: "WebTransportTests",
            dependencies: [
                "HTTP3",
                "QUIC",
                "QPACK",
                "QUICCore",
                "QUICStream",
            ],
            path: "Tests/WebTransportTests"
        ),

        .testTarget(
            name: "QuiverAuthTests",
            dependencies: [
                "QuiverAuth",
                "HTTP3",
            ],
            path: "Tests/QuiverAuthTests"
        ),

        // MARK: - Benchmarks (run separately with: swift test --filter QUICBenchmarks)

        .testTarget(
            name: "QUICBenchmarks",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "QUICStream",
                .product(name: "Crypto", package: "swift-crypto"),
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
                "NIOUDPTransport",
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
                "HTTP3",
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
                "NIOUDPTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/WebTransportDemo"
        ),

        .executableTarget(
            name: "QUICNetworkDemo",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICTransport",
                "NIOUDPTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/QUICNetworkDemo"
        ),
        .executableTarget(
            name: "AltSvcDemo",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "HTTP3",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/AltSvcDemo"
        ),
        .executableTarget(
            name: "HTTP3AuthDemo",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
                "HTTP3",
                "QuiverAuth",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/HTTP3AuthDemo"
        ),
    ]
)
