// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WireDogTunnel",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "WireDogTunnel", targets: ["WireDogTunnel"])
    ],
    dependencies: [
        // AmneziaWG fork of WireGuardKit — drop-in replacement with AWG obfuscation params
        .package(url: "https://github.com/amnezia-vpn/amneziawg-apple", from: "2.0.1")
    ],
    targets: [
        .target(
            name: "WireDogTunnel",
            dependencies: [
                .product(name: "WireGuardKit", package: "amneziawg-apple")
            ],
            path: "WireDogTunnel",
            sources: ["PacketTunnelProvider.swift"],
            linkerSettings: [
                .linkedFramework("NetworkExtension")
            ]
        )
    ]
)
