// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ContinuoSecurityTransport",
    platforms: [.macOS(.v15)],
    products: [
        .library(
            name: "ContinuoSecurityTransport",
            targets: ["ContinuoSecurityTransport"]
        )
    ],
    targets: [
        .target(name: "ContinuoSecurityTransport"),
        .testTarget(
            name: "ContinuoSecurityTransportTests",
            dependencies: ["ContinuoSecurityTransport"]
        )
    ],
    swiftLanguageModes: [.v6]
)
