// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SentryIQMaster",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "SentryIQMaster", targets: ["SentryIQMaster"])
    ],
    targets: [
        .target(name: "SentryIQMaster"),
        .testTarget(name: "SentryIQMasterTests", dependencies: ["SentryIQMaster"])
    ]
)
