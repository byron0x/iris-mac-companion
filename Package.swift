// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IRISCompanion",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "IRISCompanion", targets: ["IRISCompanion"]),
        .library(name: "IRISCore", targets: ["IRISCore"])
    ],
    targets: [
        // Official Sparkle 2.9.6 artifact, pinned to its upstream Package.swift checksum.
        .binaryTarget(name: "Sparkle", url: "https://github.com/sparkle-project/Sparkle/releases/download/2.9.6/Sparkle-for-Swift-Package-Manager.zip", checksum: "8d5fb41d960b43f4a68aa14126bf62b098544ec8d191cdcc73eb14e63a8e7606"),
        .target(name: "IRISCore"),
        .executableTarget(name: "IRISCompanion", dependencies: ["IRISCore", "Sparkle"], linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]),
        .executableTarget(name: "IRISCoreChecks", dependencies: ["IRISCore"])
    ],
    swiftLanguageVersions: [.v5]
)
