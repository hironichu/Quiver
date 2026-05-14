// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "quiver-moq",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "MOQCore", targets: ["MOQCore"]),
        .library(name: "MOQRelay", targets: ["MOQRelay"]),
        .library(name: "MOQClient", targets: ["MOQClient"]),
    ],
    dependencies: [
        .package(path: "../quiver-quic"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),
    ],
    targets: [
        .target(
            name: "MOQCore",
            dependencies: [
                .product(name: "QUICCore", package: "quiver-quic"),
            ],
            path: "Sources/MOQCore"
        ),
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
            dependencies: [],
            path: "Sources/MOQClient"
        ),
        .testTarget(
            name: "MOQCoreTests",
            dependencies: [
                "MOQCore",
                "MOQRelay",
                .product(name: "QUICCore", package: "quiver-quic"),
            ],
            path: "Tests/MOQCoreTests"
        ),
    ]
)
