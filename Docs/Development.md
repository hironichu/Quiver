# Quiver Development Guide

This document covers the split-package development workflow.

## Local Layout

The root package expects sibling package checkouts by default:

```text
workspace/
├── quiver/
└── quiver-packages/
    ├── quiver-quic/
    ├── quiver-http3/
    ├── quiver-webtransport/
    ├── quiver-auth/
    ├── quiver-adapters/
    └── quiver-moq/
```

Override the package root with:

```bash
export QUIVER_PACKAGES_PATH=/path/to/quiver-packages
```

When the local checkout exists, manifests use path dependencies. When it does not exist, manifests fall back to `https://github.com/hironichu/quiver-*.git`.

## NIO Forks And Mirrors

Some packages depend on NIO branches used for platform work. Manifests use canonical Apple package URLs for identity, and local SwiftPM mirror configuration redirects those URLs to `hironichu` forks when needed.

This avoids duplicate package identities while still allowing fork branches during development.

## Root Commands

From the root `quiver` repository:

```bash
swift package dump-package
swift build
swift test
swift build --target Quiver --traits WebTransportSupport
```

## Package Commands

From any package under `quiver-packages`:

```bash
swift package dump-package
swift build
swift test
```

`quiver-webtransport` is a facade package and may only need `swift build` unless tests are added.

## Package Traits

The root package uses SwiftPM package traits. Useful checks include:

```bash
swift build --target Quiver --traits QUICSupport
swift build --target Quiver --traits HTTP3Support
swift build --target Quiver --traits WebTransportSupport
swift build --target Quiver --traits MOQSupport
```

## Adding A New Package

1. Create or update the dedicated `quiver-*` repository.
2. Expose focused products from that package.
3. Add the dependency to root `Package.swift` with the local/GitHub fallback helper.
4. Add conditional re-exports to `Sources/Quiver/Quiver.swift`.
5. Add or update package traits.
6. Document the package in [Packages.md](Packages.md) and the package's own README.
7. Validate the dedicated package and the root aggregate build.

## Progress Tracking

Large package-split work is tracked in [../PACKAGE_SPLIT_PROGRESS.md](../PACKAGE_SPLIT_PROGRESS.md). Use short `chapter-step=ok` entries so the migration state remains easy to scan.
