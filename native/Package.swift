// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WireDogNative",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "WireDogNative", type: .dynamic, targets: ["WireDogNative"])
    ],
    targets: [
        .target(
            name: "WireDogNative",
            path: "src",
            sources: ["TunnelManager.swift", "StatusObserver.swift", "FilterExtensionManager.swift"],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Foundation")
            ]
        )
    ]
)
