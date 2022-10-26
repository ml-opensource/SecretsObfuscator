import Foundation
import PackagePlugin

@main
struct ObfuscateSecrets: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        print(arguments)
        let tool = try context.tool(named: "ObfuscateSecrets")
        let process = Process()
        process.currentDirectoryURL = URL(fileURLWithPath: context.package.directory.string)
        process.executableURL = URL(fileURLWithPath: tool.path.string)
        process.arguments = arguments
        
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = stdout
        
        try process.run()
        process.waitUntilExit()
        
        guard
            let outputData = try stdout.fileHandleForReading.readToEnd(),
            let outputText = String(data: outputData, encoding: .utf8)
        else {
            return
        }
        
        print(outputText)
    }
}
