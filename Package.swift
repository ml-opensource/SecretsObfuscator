// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ObfuscateSecrets",
    products: [
        .executable(
            name: "ObfuscateSecrets",
            targets: ["ObfuscateSecrets"]
        ),
        .plugin(
            name: "ObfuscateSecretsPlugin",
            targets: ["ObfuscateSecretsPlugin"]
        )
    ],
    targets: [
        .executableTarget(name: "ObfuscateSecrets"),
        .plugin(
            name: "ObfuscateSecretsPlugin",
            capability: .command(
                intent: .custom(
                    verb: "obfuscate-secrets",
                    description: "Obfuscate secrets"),
                permissions: [
                    .writeToPackageDirectory(reason: "Generate Secrets file")
                ]),
            dependencies: [
                "ObfuscateSecrets"
            ]
        )
    ]
)
