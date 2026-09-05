// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "IRISCompanion", platforms: [.macOS(.v13)], products: [.executable(name: "IRISCompanion", targets: ["IRISCompanion"]), .library(name: "IRISCore", targets: ["IRISCore"])], targets: [.target(name: "IRISCore"), .executableTarget(name: "IRISCompanion", dependencies: ["IRISCore"]), .executableTarget(name: "IRISCoreChecks", dependencies: ["IRISCore"])], swiftLanguageVersions: [.v5])
