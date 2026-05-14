// swift-tools-version: 6.2

import PackageDescription

let useLocalDeps = Context.environment["SWIFTCI_USE_LOCAL_DEPS"] != nil

func nioDependencies() -> [Package.Dependency] {
    if useLocalDeps {
        return [
            .package(path: "../../swift-nio"),
            .package(path: "../../swift-nio-ssl"),
        ]
    } else {
        return [
            .package(url: "https://github.com/hironichu/swift-nio.git", branch: "pr-3433"),
            .package(url: "https://github.com/hironichu/swift-nio-ssl.git", branch: "pr-567-windows-support"),
        ]
    }
}

let package = Package(
    name: "quiver-http3",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "QPACK", targets: ["QPACK"]),
        .library(name: "HTTP3", targets: ["HTTP3"]),
    ],
    dependencies: nioDependencies() + [
        .package(path: "../quiver-quic"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),
    ],
    targets: [
        .target(
            name: "QPACK",
            dependencies: [],
            path: "Sources/QPACK"
        ),
        .target(
            name: "HTTP3",
            dependencies: [
                .product(name: "QUIC", package: "quiver-quic"),
                "QPACK",
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QUICCrypto", package: "quiver-quic"),
                .product(name: "QUICStream", package: "quiver-quic"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/HTTP3"
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
                .product(name: "QUIC", package: "quiver-quic"),
                "QPACK",
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "QuiverTestSupport", package: "quiver-quic"),
            ],
            path: "Tests/HTTP3Tests"
        ),
    ]
)
