// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "wiredog-sysext-activate",
    platforms: [.macOS(.v12)],
    targets: [
        .executableTarget(
            name: "wiredog-sysext-activate",
            path: "Sources",
            linkerSettings: [
                .linkedFramework("SystemExtensions")
            ]
        )
    ]
)
