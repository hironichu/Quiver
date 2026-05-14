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
        .package(path: "Packages/quiver-quic"),
        .package(path: "Packages/quiver-http3"),
        .package(path: "Packages/quiver-auth"),
        .package(path: "Packages/quiver-adapters"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.5.0"),
    ],
    targets: [
        // MARK: - MOQ Core
        .target(
            name: "MOQCore",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICStream", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQCore"
        ),

        // MARK: - MOQ Relay & Client
        .target(
            name: "MOQRelay",
            dependencies: [
                "MOQCore",
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQRelay"
        ),

        .target(
            name: "MOQClient",
            dependencies: [
                "MOQCore",
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/MOQClient"
        ),

        // MARK: - Tests
        .testTarget(
            name: "MOQCoreTests",
            dependencies: [
                "MOQCore",
                "MOQRelay",
                .product(name: "QUICCore", package: "quiver-quic"),
            ],
            path: "Tests/MOQCoreTests"
        ),

        .testTarget(
            name: "WebTransportTests",
            dependencies: [
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QPACK", package: "quiver-http3"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICStream", package: "quiver-quic"),
            ],
            path: "Tests/WebTransportTests"
        ),

        // MARK: - Examples
        .executableTarget(
            name: "QUICEchoServer",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "QUICTransport", package: "quiver-quic"),
                .product(name: "NIOUDPTransport", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/QUICEchoServer"
        ),

        .executableTarget(
            name: "HTTP3Demo",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/HTTP3Demo"
        ),

        .executableTarget(
            name: "HTTP3Benchmark",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/HTTP3Benchmark"
        ),

        .executableTarget(
            name: "WebTransportDemo",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "QUICTransport", package: "quiver-quic"),
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "QPACK", package: "quiver-http3"),
                .product(name: "NIOUDPTransport", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/WebTransportDemo"
        ),

        .executableTarget(
            name: "QUICNetworkDemo",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "QUICConnection", package: "quiver-quic"),
                .product(name: "QUICTransport", package: "quiver-quic"),
                .product(name: "NIOUDPTransport", package: "quiver-quic"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/QUICNetworkDemo"
        ),
        .executableTarget(
            name: "AltSvcDemo",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/AltSvcDemo"
        ),
        .executableTarget(
            name: "HTTP3AuthDemo",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "QuiverAuth", package: "quiver-auth"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Examples/HTTP3AuthDemo"
        ),
    ]
)
