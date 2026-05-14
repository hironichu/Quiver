// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "quiver-webtransport",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "WebTransport", targets: ["WebTransport"]),
    ],
    dependencies: [
        .package(path: "../quiver-http3"),
    ],
    targets: [
        .target(
            name: "WebTransport",
            dependencies: [
                .product(name: "HTTP3", package: "quiver-http3"),
            ],
            path: "Sources/WebTransport"
        ),
    ]
)
