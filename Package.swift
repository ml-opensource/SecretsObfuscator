// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ObfuscateSecrets",
    products: [
        .executable(name: "gen-secrets", targets: ["gen-secrets"])
    ],
    targets: [
        .executableTarget(name: "gen-secrets")
    ]
)
