// swift-tools-version: 6.2

import Foundation
import PackageDescription

let useLocalDeps = Context.environment["SWIFTCI_USE_LOCAL_DEPS"] != nil
let localDependencyPrefix = FileManager.default.fileExists(atPath: "../../swift-nio") ? "../.." : ".."

func nioDependencies() -> [Package.Dependency] {
    if useLocalDeps {
        return [
            .package(path: "\(localDependencyPrefix)/swift-nio"),
            .package(path: "\(localDependencyPrefix)/swift-nio-ssl"),
            .package(path: "\(localDependencyPrefix)/swift-system"),
        ]
    } else {
        return [
            .package(url: "https://github.com/hironichu/swift-nio.git", branch: "pr-3433"),
            .package(url: "https://github.com/hironichu/swift-nio-ssl.git", branch: "pr-567-windows-support"),
            .package(url: "https://github.com/apple/swift-system.git", from: "1.6.4"),
        ]
    }
}

let package = Package(
    name: "quiver-quic",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "QUIC", targets: ["QUIC"]),
        .library(name: "QUICCore", targets: ["QUICCore"]),
        .library(name: "QUICCrypto", targets: ["QUICCrypto"]),
        .library(name: "QUICStream", targets: ["QUICStream"]),
        .library(name: "QUICRecovery", targets: ["QUICRecovery"]),
        .library(name: "QUICTransport", targets: ["QUICTransport"]),
        .library(name: "NIOUDPTransport", targets: ["NIOUDPTransport"]),
        .library(name: "QUICConnection", targets: ["QUICConnection"]),
        .library(name: "QuiverTestSupport", targets: ["QuiverTestSupport"]),
    ],
    dependencies: nioDependencies() + [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.5.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.12.0"),
    ],
    targets: [
        .target(
            name: "QUICCore",
            dependencies: [
                .product(name: "Logging", package: "swift-log")
            ],
            path: "Sources/QUICCore"
        ),
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
        .target(
            name: "NIOUDPTransport",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/NIOUDPTransport"
        ),
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
        .target(
            name: "QUICStream",
            dependencies: [
                "QUICCore",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUICStream"
        ),
        .target(
            name: "QUICRecovery",
            dependencies: [
                "QUICCore"
            ],
            path: "Sources/QUICRecovery"
        ),
        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
                "NIOUDPTransport",
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/QUICTransport"
        ),
        .target(
            name: "QUIC",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICStream",
                "QUICRecovery",
                "QUICTransport",
                "NIOUDPTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUIC"
        ),
        .target(
            name: "QuiverTestSupport",
            dependencies: [
                "QUICCore"
            ],
            path: "Sources/QuiverTestSupport"
        ),
        .testTarget(
            name: "QUICCoreTests",
            dependencies: ["QUICCore"],
            path: "Tests/QUICCoreTests"
        ),
        .testTarget(
            name: "QUICCryptoTests",
            dependencies: ["QUICCrypto", "QUICCore"],
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
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICRecovery",
                "QUICTransport",
                "QuiverTestSupport",
            ],
            path: "Tests/QUICTests"
        ),
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
    ]
)
