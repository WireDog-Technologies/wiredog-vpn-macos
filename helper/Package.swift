// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "wiredog-helper",
    platforms: [.macOS(.v12)],
    targets: [
        .executableTarget(
            name: "wiredog-helper",
            path: "Sources",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions")
            ]
        )
    ]
)
