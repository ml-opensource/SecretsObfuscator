import Foundation
import CommonCrypto

public enum GenerateSecretsError: Int32, Error {
    case invalidArgumentsCount = 1
    case specReadingFailed = 2
    case specDecodingFailed = 3
    case writingToFileFailed = 4
    case specWithNoSecrets = 5
}

enum Placeholder {
    static let filename = "{{filename}}"
    static let key = "{{key}}"
    static let secrets = "{{secrets}}"
    static let enumCases = "{{enumCases}}"
}

struct SecretsSpec: Codable {
    var key: String
    var secrets: [String: String]
}

extension SecretsSpec {
    private struct SecretData {
        var key: String
        var data: Data
        var offset: Int
    }
    
    func generateSecrets(name: String) -> String {
        let template = """
        import Foundation

        /// Secrets.
        enum \(Placeholder.filename): UInt64, CaseIterable {
            \(Placeholder.enumCases)
            /// Outputs the secret in plain text
            var value: String {
                // Calculate secret's range (lowerbound and upperbound)
                let lb = Int((rawValue ^ 0xba34ef119cbe589d) & 0xffffffff)
                let ub = Int((rawValue ^ 0xba34ef119cbe589d) >> 32 & 0xffffffff)
                
                // Decrypt secret in range [lowerbound..<upperbound]
                let o = Self.d[lb..<ub]
                    .enumerated()
                    .map { $0.element ^ Self.k[($0.offset + lb) % Self.k.count] }

                return String(data: Data(o), encoding: .utf8)!
            }

            /// Key used to encrypt and decrypt secrets
            private static let k: [UInt8] = [
                \(Placeholder.key)
            ]

            /// Secrets in byte form.
            private static let d: [UInt8] = [
                \(Placeholder.secrets)
            ]
        }

        """
        
        let secretsData = secretsData(secrets: secrets)
        let keyData = sha256(Data(key.utf8))
        let key = key(keyData)
        let enumCases = enumCases(secretsData)
        let secrets = secrets(keyData, secretsData)
        
        return template
            .replacingOccurrences(of: Placeholder.filename, with: name)
            .replacingOccurrences(of: Placeholder.key, with: key)
            .replacingOccurrences(of: Placeholder.enumCases, with: enumCases)
            .replacingOccurrences(of: Placeholder.secrets, with: secrets)
    }
    
    private func sha256(_ data: Data) -> Data {
        return data.withUnsafeBytes { rawBuffer -> Data in
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256(rawBuffer.baseAddress!, CC_LONG(rawBuffer.count), &hash)
            return Data(hash)
        }
    }
    
    private func key(_ keyData: Data) -> String {
        return keyData
            .chunked(into: 8)
            .map { chunk in
                chunk
                    .map { String(format: "0x%02X", $0) }
                    .joined(separator: ", ")
            }
            .joined(separator: ",\n        ")
    }
    
    private func enumCases(_ secretsData: [SecretData]) -> String {
        return secretsData
            .enumerated()
            .map { e in
                let lowerBound = UInt64(e.element.offset)
                let upperBound = UInt64(e.element.offset + e.element.data.count) << 32
                let range = (lowerBound | upperBound) ^ 0xba34ef119cbe589d
                
                return "/// \(e.element.key.capitalized)\n    case _\(e.offset+1) = \(range)\n"
            }
            .joined(separator: "\n    ")
    }
    
    private func secrets(_ keyData: Data, _ secretsData: [SecretData]) -> String {
        // Join all secrets' data together
        let secret = Data(secretsData.flatMap(\.data))
        
        return encrypt(secret: secret, key: keyData)
            .chunked(into: 8)
            .map { chunk in
                chunk
                    .map { String(format: "0x%02X", $0) }
                    .joined(separator: ", ")
            }
            .joined(separator: ",\n        ")
    }
    
    private func secretsData(secrets: [String: String]) -> [SecretData] {
        guard !secrets.isEmpty else { return [] }
        
        var output = [SecretData]()
        var offset = 0
        
        for (key, value) in secrets.sorted(by: { $0.key < $1.key }) where !value.isEmpty {
            let data = Data(value.utf8)
            
            output.append(SecretData(key: key, data: data, offset: offset))
            
            offset += data.count
        }
        
        return output
    }
    
    /// Encrypts `secret` using `key`.
    /// - Parameters:
    ///   - secret: plain text secret as a byte buffer.
    ///   - key: encryption key as a byte buffer.
    /// - Returns: encrypted secret.
    private func encrypt(secret: Data, key: Data) -> Data {
        assert(!key.isEmpty)

        let bytes = secret
            .enumerated()
            .map { $0.element ^ key[$0.offset % key.count] }
        
        return Data(bytes)
    }
}

extension Data {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}

extension Array {
    subscript(safe index: Int) -> Element? {
        return index < count ? self[index] : nil
    }
}

func generateSecrets(inputData: Data, name: String, key: String) throws -> String {
    let spec: SecretsSpec
    
    do {
        let secrets = try JSONDecoder().decode([String: String].self, from: inputData)
        
        spec = SecretsSpec(key: key, secrets: secrets)
    } catch {
        print("Failed decoding file: \(error)")
        throw GenerateSecretsError.specDecodingFailed
    }
    
    guard !spec.secrets.isEmpty else {
        throw GenerateSecretsError.specWithNoSecrets
    }
    
    let name = name.replacingOccurrences(of: ".swift", with: "")
    
    return spec.generateSecrets(name: name)
}

func generateSecrets(inputUrl: URL, name: String, key: String) throws -> String {
    let specData: Data

    do {
        specData = try Data(contentsOf: inputUrl)
    } catch {
        print("Failed reading file: \(error)")
        throw GenerateSecretsError.specReadingFailed
    }

    return try generateSecrets(inputData: specData, name: name, key: key)
}

func generateSecrets(inputData: Data, outputUrl: URL, key: String) throws {
    let name = outputUrl.deletingPathExtension().lastPathComponent
    let output = try generateSecrets(inputData: inputData, name: name, key: key)
    
    do {
        try output.write(to: outputUrl, atomically: true, encoding: .utf8)
    } catch {
        print("Failed to write to output file: \(error)")
        throw GenerateSecretsError.writingToFileFailed
    }
}

func generateSecrets(inputUrl: URL, outputUrl: URL, key: String) throws {
    let specData: Data

    do {
        specData = try Data(contentsOf: inputUrl)
    } catch {
        print("Failed reading file: \(error)")
        throw GenerateSecretsError.specReadingFailed
    }
    
    try generateSecrets(inputData: specData, outputUrl: outputUrl, key: key)
}

func retrieveNamedArguments(_ args: [String]) -> (args: [String], named: [String: String]) {
    let namedArgsIndexes = args.enumerated().filter { $0.element.hasPrefix("-") }.map(\.offset)
    var namedArgs = [String: String]()
    var removedArgs = Set<String>()
    
    for i in namedArgsIndexes {
        if i + 1 < args.count && !args[i + 1].hasPrefix("-") {
            namedArgs[args[i]] = args[i + 1]
            removedArgs.insert(args[i + 1])
        } else {
            namedArgs[args[i]] = ""
        }
        
        removedArgs.insert(args[i])
    }
    
    var copy = args
    copy.removeAll(where: removedArgs.contains)
    
    return (args: copy, named: namedArgs)
}

let arguments = Array(ProcessInfo().arguments.dropFirst())
let (nonNamedArgs, namedArgs) = retrieveNamedArguments(arguments)

guard nonNamedArgs.count >= 1 else {
    print("""
    Usage: gen-secrets <secrets.json> [<output swift file>]

    \u{1B}[1m-k <password>\u{1B}[0m          Key used to encrypt secrets

    Examples:

    obfuscate-secrets secrets.json > SData.swift
    obfuscate-secrets secrets.json SData.swift
    obfuscate-secrets secrets.json

    """)

    exit(GenerateSecretsError.invalidArgumentsCount.rawValue)
}

do {
    let inputUrl = URL(fileURLWithPath: nonNamedArgs[0])
    let key = namedArgs["-k"] ?? namedArgs["-key"] ?? namedArgs["--key"] ?? UUID().uuidString

    if nonNamedArgs.count >= 2 {
        let outputUrl = URL(fileURLWithPath: nonNamedArgs[1])
        
        try generateSecrets(inputUrl: inputUrl, outputUrl: outputUrl, key: key)

        print("\u{1B}[0;32m\(outputUrl.lastPathComponent) successfully generated.")
    } else {
        print(try generateSecrets(inputUrl: inputUrl, name: "SData.swift", key: key))
    }
} catch let error as GenerateSecretsError {
    exit(error.rawValue)
}
