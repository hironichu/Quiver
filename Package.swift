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
        .library(name: "Quiver", targets: ["Quiver"]),
    ],
    traits: [
        .default(enabledTraits: [
            "QUICSupport",
            "HTTP3Support",
            "WebTransportSupport",
            "AuthSupport",
            "VaporSupport",
            "HummingbirdSupport",
            "MOQSupport",
        ]),
        .trait(name: "QUICSupport", description: "Expose Quiver QUIC products."),
        .trait(name: "HTTP3Support", description: "Expose HTTP/3 and QPACK products.", enabledTraits: ["QUICSupport"]),
        .trait(name: "WebTransportSupport", description: "Expose WebTransport APIs hosted by HTTP3.", enabledTraits: ["HTTP3Support"]),
        .trait(name: "AuthSupport", description: "Expose QuiverAuth APIs.", enabledTraits: ["HTTP3Support"]),
        .trait(name: "VaporSupport", description: "Expose Vapor adapter APIs.", enabledTraits: ["HTTP3Support"]),
        .trait(name: "HummingbirdSupport", description: "Expose Hummingbird adapter APIs.", enabledTraits: ["HTTP3Support"]),
        .trait(name: "MOQSupport", description: "Expose Media over QUIC products.", enabledTraits: ["QUICSupport"]),
    ],
    dependencies: [
        .package(path: "Packages/quiver-quic"),
        .package(path: "Packages/quiver-http3"),
        .package(path: "Packages/quiver-auth"),
        .package(path: "Packages/quiver-adapters"),
        .package(path: "Packages/quiver-moq"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "Quiver",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICCore", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICCrypto", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICStream", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICRecovery", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICTransport", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "NIOUDPTransport", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "QUICConnection", package: "quiver-quic", condition: .when(traits: ["QUICSupport"])),
                .product(name: "HTTP3", package: "quiver-http3", condition: .when(traits: ["HTTP3Support"])),
                .product(name: "QPACK", package: "quiver-http3", condition: .when(traits: ["HTTP3Support"])),
                .product(name: "QuiverAuth", package: "quiver-auth", condition: .when(traits: ["AuthSupport"])),
                .product(name: "QuiverVapor", package: "quiver-adapters", condition: .when(traits: ["VaporSupport"])),
                .product(name: "QuiverHummingbird", package: "quiver-adapters", condition: .when(traits: ["HummingbirdSupport"])),
                .product(name: "MOQCore", package: "quiver-moq", condition: .when(traits: ["MOQSupport"])),
                .product(name: "MOQRelay", package: "quiver-moq", condition: .when(traits: ["MOQSupport"])),
                .product(name: "MOQClient", package: "quiver-moq", condition: .when(traits: ["MOQSupport"])),
            ],
            path: "Sources/Quiver",
            swiftSettings: [
                .define("QUIVER_QUIC_SUPPORT", .when(traits: ["QUICSupport"])),
                .define("QUIVER_HTTP3_SUPPORT", .when(traits: ["HTTP3Support"])),
                .define("QUIVER_AUTH_SUPPORT", .when(traits: ["AuthSupport"])),
                .define("QUIVER_VAPOR_SUPPORT", .when(traits: ["VaporSupport"])),
                .define("QUIVER_HUMMINGBIRD_SUPPORT", .when(traits: ["HummingbirdSupport"])),
                .define("QUIVER_MOQ_SUPPORT", .when(traits: ["MOQSupport"])),
            ]
        ),

        // MARK: - Tests
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
