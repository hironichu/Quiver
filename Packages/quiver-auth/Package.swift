// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "quiver-auth",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "QuiverAuth", targets: ["QuiverAuth"]),
    ],
    dependencies: [
        .package(path: "../quiver-http3"),
        .package(path: "../quiver-quic"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.5.0"),
    ],
    targets: [
        .target(
            name: "QuiverAuth",
            dependencies: [
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "QUICCore", package: "quiver-quic"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            path: "Sources/QuiverAuth"
        ),
        .testTarget(
            name: "QuiverAuthTests",
            dependencies: [
                "QuiverAuth",
                .product(name: "HTTP3", package: "quiver-http3"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Tests/QuiverAuthTests"
        ),
    ]
)
