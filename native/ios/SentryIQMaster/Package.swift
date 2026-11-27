// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SentryIQMaster",
    platforms: [
        .iOS(.v13),
        .macOS(.v14)
    ],
    products: [
        .library(name: "SentryIQMaster", targets: ["SentryIQMaster"])
    ],
    targets: [
        .binaryTarget(
            name: "SentryIQTufCoreFFI",
            path: "Libraries/SentryIQTufCore.xcframework"
        ),
        .target(
            name: "SentryIQTufCoreBindings",
            dependencies: ["SentryIQTufCoreFFI"]
        ),
        .target(
            name: "SentryIQMaster",
            dependencies: ["SentryIQTufCoreBindings"]
        ),
        .testTarget(name: "SentryIQMasterTests", dependencies: ["SentryIQMaster"], resources: [.copy("Fixtures")])
    ]
)
