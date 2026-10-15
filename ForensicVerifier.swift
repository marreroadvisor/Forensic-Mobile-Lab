import CryptoKit
import Foundation
import Security

private struct Entry: Codable, Comparable {
    let path: String
    let size: UInt64
    let sha256: String

    static func < (lhs: Entry, rhs: Entry) -> Bool { lhs.path < rhs.path }
}

private struct Seal: Codable {
    let schema: Int
    let algorithm: String
    let signedAtUTC: String
    let publicKeyBase64: String
    let publicKeyFingerprintSHA256: String
    let manifestSHA256: String
    let signatureBase64: String
    let files: [Entry]
}

private enum VerifierError: LocalizedError {
    case usage, invalidCase, invalidSeal, signatureInvalid, manifestChanged(String), invalidPassword, invalidArchive
    var errorDescription: String? {
        switch self {
        case .usage: return "Uso: ForensicVerifier seal|verify <caso> | encrypt|decrypt <origen> <destino>"
        case .invalidCase: return "La carpeta del expediente no existe o no es válida."
        case .invalidSeal: return "El sello criptográfico no existe o tiene un formato inválido."
        case .signatureInvalid: return "La firma Ed25519 no es válida."
        case .manifestChanged(let detail): return "El contenido del expediente cambió: \(detail)"
        case .invalidPassword: return "La contraseña debe contener al menos 12 caracteres."
        case .invalidArchive: return "El archivo FMLX está dañado, fue alterado o la contraseña es incorrecta."
        }
    }
}

private let encoder: JSONEncoder = {
    let value = JSONEncoder()
    value.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return value
}()

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func hashFile(_ url: URL) throws -> (UInt64, String) {
    let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true else { throw VerifierError.invalidCase }
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var digest = SHA256()
    while true {
        let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
        if chunk.isEmpty { break }
        digest.update(data: chunk)
    }
    return (UInt64(values.fileSize ?? 0), digest.finalize().map { String(format: "%02x", $0) }.joined())
}

private func entries(in root: URL) throws -> [Entry] {
    let manager = FileManager.default
    guard let enumerator = manager.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
        options: []
    ) else { throw VerifierError.invalidCase }
    let rootPath = root.standardizedFileURL.path + "/"
    var result: [Entry] = []
    for case let file as URL in enumerator {
        let standardized = file.standardizedFileURL
        guard standardized.path.hasPrefix(rootPath) else { throw VerifierError.invalidCase }
        let relative = String(standardized.path.dropFirst(rootPath.count))
        if relative == "reports/case_signature.json" || relative == "reports/integrity_verification.json" || relative.hasSuffix(".partial") || relative.split(separator: "/").contains(".ui_cache") { continue }
        let values = try standardized.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true { throw VerifierError.manifestChanged("se encontró un enlace simbólico no permitido: \(relative)") }
        guard values.isRegularFile == true else { continue }
        let (size, hash) = try hashFile(standardized)
        result.append(Entry(path: relative, size: size, sha256: hash))
    }
    return result.sorted()
}

private func manifestData(_ entries: [Entry]) throws -> Data { try encoder.encode(entries) }

private func keyURL() throws -> URL {
    let base = try FileManager.default.url(
        for: .applicationSupportDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true
    ).appendingPathComponent("ForensicMobileLab", isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return base.appendingPathComponent("ed25519-signing-key.bin")
}

private func signingKey() throws -> Curve25519.Signing.PrivateKey {
    let url = try keyURL()
    if FileManager.default.fileExists(atPath: url.path) {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else { throw VerifierError.invalidCase }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let permissions = attributes[.posixPermissions] as? NSNumber,
              permissions.intValue & 0o077 == 0 else { throw VerifierError.invalidCase }
        let raw = try Data(contentsOf: url)
        guard raw.count == 32 else { throw VerifierError.invalidCase }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    }
    let key = Curve25519.Signing.PrivateKey()
    try key.rawRepresentation.write(to: url, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    return key
}

private let fmlxMagic = Data("FMLX0001".utf8)
private let fmlxIterations: UInt32 = 200_000
private let fmlxChunkSize = 4 * 1024 * 1024

private func be32(_ value: UInt32) -> Data {
    var big = value.bigEndian
    return Data(bytes: &big, count: MemoryLayout<UInt32>.size)
}

private func read32(_ handle: FileHandle) throws -> UInt32 {
    let data = try handle.read(upToCount: 4) ?? Data()
    guard data.count == 4 else { throw VerifierError.invalidArchive }
    return data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
}

private func pbkdf2(password: Data, salt: Data, iterations: UInt32) -> SymmetricKey {
    let passwordKey = SymmetricKey(data: password)
    var firstInput = salt
    firstInput.append(be32(1))
    var value = Data(HMAC<SHA256>.authenticationCode(for: firstInput, using: passwordKey))
    var output = value
    if iterations > 1 {
        for _ in 2...iterations {
            value = Data(HMAC<SHA256>.authenticationCode(for: value, using: passwordKey))
            for index in output.indices { output[index] ^= value[index] }
        }
    }
    return SymmetricKey(data: output)
}

private func passwordFromStdin() throws -> Data {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .newlines)
    guard value.count >= 12 else { throw VerifierError.invalidPassword }
    return Data(value.utf8)
}

private func encrypt(source: URL, destination: URL) throws {
    let password = try passwordFromStdin()
    var salt = Data(count: 16)
    let status = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
    guard status == errSecSuccess else { throw VerifierError.invalidArchive }
    let key = pbkdf2(password: password, salt: salt, iterations: fmlxIterations)
    let input = try FileHandle(forReadingFrom: source)
    let temporary = destination.deletingLastPathComponent().appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
    guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
        throw VerifierError.invalidArchive
    }
    let output = try FileHandle(forWritingTo: temporary)
    var succeeded = false
    defer {
        try? input.close(); try? output.close()
        if !succeeded { try? FileManager.default.removeItem(at: temporary) }
    }
    try output.write(contentsOf: fmlxMagic)
    try output.write(contentsOf: salt)
    try output.write(contentsOf: be32(fmlxIterations))
    try output.write(contentsOf: be32(UInt32(fmlxChunkSize)))
    var index: UInt32 = 0
    while true {
        let chunk = try input.read(upToCount: fmlxChunkSize) ?? Data()
        if chunk.isEmpty { break }
        let sealed = try AES.GCM.seal(chunk, using: key, authenticating: fmlxMagic + be32(index))
        guard let combined = sealed.combined else { throw VerifierError.invalidArchive }
        try output.write(contentsOf: be32(UInt32(chunk.count)))
        try output.write(contentsOf: be32(UInt32(combined.count)))
        try output.write(contentsOf: combined)
        index &+= 1
    }
    let final = try AES.GCM.seal(Data(), using: key, authenticating: fmlxMagic + be32(index))
    guard let combined = final.combined else { throw VerifierError.invalidArchive }
    try output.write(contentsOf: be32(0))
    try output.write(contentsOf: be32(UInt32(combined.count)))
    try output.write(contentsOf: combined)
    try output.synchronize()
    try output.close()
    if FileManager.default.fileExists(atPath: destination.path) {
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
    } else {
        try FileManager.default.moveItem(at: temporary, to: destination)
    }
    succeeded = true
    print("FMLX CIFRADO CON AES-256-GCM")
    print("Bloques: \(index)")
}

private func decrypt(source: URL, destination: URL) throws {
    let password = try passwordFromStdin()
    let input = try FileHandle(forReadingFrom: source)
    defer { try? input.close() }
    guard try input.read(upToCount: fmlxMagic.count) == fmlxMagic else { throw VerifierError.invalidArchive }
    let salt = try input.read(upToCount: 16) ?? Data()
    guard salt.count == 16 else { throw VerifierError.invalidArchive }
    let iterations = try read32(input)
    let chunkSize = try read32(input)
    guard (100_000...1_000_000).contains(iterations), chunkSize == UInt32(fmlxChunkSize) else { throw VerifierError.invalidArchive }
    let key = pbkdf2(password: password, salt: salt, iterations: iterations)
    let temporary = destination.deletingLastPathComponent().appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
    _ = FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let output = try FileHandle(forWritingTo: temporary)
    var succeeded = false
    defer {
        try? output.close()
        if !succeeded { try? FileManager.default.removeItem(at: temporary) }
    }
    var index: UInt32 = 0
    while true {
        let plainCount = try read32(input)
        let sealedCount = try read32(input)
        guard sealedCount >= 28, sealedCount <= UInt32(fmlxChunkSize + 28) else { throw VerifierError.invalidArchive }
        let combined = try input.read(upToCount: Int(sealedCount)) ?? Data()
        guard combined.count == Int(sealedCount) else { throw VerifierError.invalidArchive }
        let box = try AES.GCM.SealedBox(combined: combined)
        let plain: Data
        do { plain = try AES.GCM.open(box, using: key, authenticating: fmlxMagic + be32(index)) }
        catch { throw VerifierError.invalidArchive }
        guard plain.count == Int(plainCount) else { throw VerifierError.invalidArchive }
        if plainCount == 0 {
            guard (try input.read(upToCount: 1) ?? Data()).isEmpty else { throw VerifierError.invalidArchive }
            break
        }
        try output.write(contentsOf: plain)
        index &+= 1
    }
    try output.close()
    if FileManager.default.fileExists(atPath: destination.path) { try FileManager.default.removeItem(at: destination) }
    try FileManager.default.moveItem(at: temporary, to: destination)
    succeeded = true
    print("FMLX DESCIFRADO Y AUTENTICADO")
    print("Bloques: \(index)")
}

private func seal(_ root: URL) throws {
    let files = try entries(in: root)
    guard !files.isEmpty else { throw VerifierError.invalidCase }
    let canonical = try manifestData(files)
    let key = try signingKey()
    let publicKey = key.publicKey.rawRepresentation
    let signature = try key.signature(for: canonical)
    let payload = Seal(
        schema: 1,
        algorithm: "Ed25519",
        signedAtUTC: ISO8601DateFormatter().string(from: Date()),
        publicKeyBase64: publicKey.base64EncodedString(),
        publicKeyFingerprintSHA256: sha256(publicKey),
        manifestSHA256: sha256(canonical),
        signatureBase64: signature.base64EncodedString(),
        files: files
    )
    let reportDir = root.appendingPathComponent("reports", isDirectory: true)
    try FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let destination = reportDir.appendingPathComponent("case_signature.json")
    let pretty = JSONEncoder(); pretty.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    try pretty.encode(payload).write(to: destination, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    print("SELLO ED25519 CREADO")
    print("Archivos: \(files.count)")
    print("Huella de clave: \(payload.publicKeyFingerprintSHA256)")
    print("Manifiesto: \(payload.manifestSHA256)")
}

private func verify(_ root: URL) throws {
    let signatureURL = root.appendingPathComponent("reports/case_signature.json")
    guard let payload = try? JSONDecoder().decode(Seal.self, from: Data(contentsOf: signatureURL)),
          payload.schema == 1, payload.algorithm == "Ed25519",
          let publicData = Data(base64Encoded: payload.publicKeyBase64),
          let signature = Data(base64Encoded: payload.signatureBase64) else { throw VerifierError.invalidSeal }
    let current = try entries(in: root)
    guard current == payload.files else {
        let expected = Set(payload.files.map(\.path)), actual = Set(current.map(\.path))
        let added = actual.subtracting(expected).sorted()
        let removed = expected.subtracting(actual).sorted()
        let changed = current.filter { value in payload.files.first(where: { $0.path == value.path }) != value }.map(\.path)
        throw VerifierError.manifestChanged("añadidos=\(added), eliminados=\(removed), modificados=\(changed)")
    }
    let canonical = try manifestData(current)
    guard sha256(canonical) == payload.manifestSHA256 else { throw VerifierError.manifestChanged("la huella del manifiesto no coincide") }
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicData)
    guard sha256(publicData) == payload.publicKeyFingerprintSHA256 else {
        throw VerifierError.invalidSeal
    }
    guard publicKey.isValidSignature(signature, for: canonical) else { throw VerifierError.signatureInvalid }
    print("FIRMA ED25519 VÁLIDA")
    print("Archivos verificados: \(current.count)")
    print("Huella de clave: \(payload.publicKeyFingerprintSHA256)")
    print("Manifiesto: \(payload.manifestSHA256)")
}

do {
    guard CommandLine.arguments.count >= 2 else { throw VerifierError.usage }
    switch CommandLine.arguments[1] {
    case "seal", "verify":
        guard CommandLine.arguments.count == 3 else { throw VerifierError.usage }
        let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true).standardizedFileURL
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else { throw VerifierError.invalidCase }
        if CommandLine.arguments[1] == "seal" { try seal(root) } else { try verify(root) }
    case "encrypt", "decrypt":
        guard CommandLine.arguments.count == 4 else { throw VerifierError.usage }
        let source = URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL
        let destination = URL(fileURLWithPath: CommandLine.arguments[3]).standardizedFileURL
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              source != destination else { throw VerifierError.invalidArchive }
        if CommandLine.arguments[1] == "encrypt" { try encrypt(source: source, destination: destination) }
        else { try decrypt(source: source, destination: destination) }
    default: throw VerifierError.usage
    }
} catch {
    FileHandle.standardError.write(Data("ERROR: \(error.localizedDescription)\n".utf8))
    exit(1)
}
