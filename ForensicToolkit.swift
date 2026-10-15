import AppKit
import CryptoKit
import Foundation
import UniformTypeIdentifiers
import Vision

final class ForensicToolkitController: NSWindowController {
    private let python: URL
    private let engine: URL
    private let reportsRoot: URL
    private let output = NSTextView()
    private let status = NSTextField(labelWithString: "● LISTO")
    private var actionButtons: [NSButton] = []

    init(python: URL, engine: URL, reportsRoot: URL) {
        self.python = python
        self.engine = engine
        self.reportsRoot = reportsRoot
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered, defer: false
        )
        window.title = "Kit Forense — Forensic Mobile Lab"
        super.init(window: window)
        buildUI()
    }

    required init?(coder: NSCoder) { nil }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor(calibratedRed: 0.035, green: 0.065, blue: 0.080, alpha: 1).cgColor
        let title = NSTextField(labelWithString: "KIT FORENSE")
        title.font = .systemFont(ofSize: 25, weight: .bold)
        title.textColor = NSColor(calibratedRed: 0.31, green: 0.91, blue: 0.69, alpha: 1)
        let subtitle = NSTextField(labelWithString: "Herramientas locales · resultados reproducibles · sin modificar evidencia")
        subtitle.textColor = .secondaryLabelColor

        let actions: [(String, Selector)] = [
            ("Hash SHA-256 / CRC32", #selector(hashFile)),
            ("Visor hexadecimal", #selector(hexViewer)),
            ("Conversor timestamps", #selector(convertTimestamp)),
            ("Auditar SQLite / WAL", #selector(sqliteAudit)),
            ("Analizar APK", #selector(apkAudit)),
            ("OCR local", #selector(runOCR)),
            ("Inventario Android", #selector(androidInventory)),
            ("Contactos y SMS", #selector(androidCommunications)),
            ("Historial Chrome", #selector(chromeHistory)),
        ]
        let buttons = actions.map { title, selector -> NSButton in
            let button = NSButton(title: title, target: self, action: selector)
            button.bezelStyle = .rounded
            button.font = .systemFont(ofSize: 12, weight: .semibold)
            button.contentTintColor = NSColor(calibratedRed: 0.20, green: 0.82, blue: 0.95, alpha: 1)
            return button
        }
        actionButtons = buttons
        let buttonGrid = NSGridView(views: stride(from: 0, to: buttons.count, by: 3).map { start in
            (0..<3).map { offset -> NSView in
                let index = start + offset
                return index < buttons.count ? buttons[index] : NSView()
            }
        })
        buttonGrid.rowSpacing = 8
        buttonGrid.columnSpacing = 8
        buttonGrid.xPlacement = .fill

        output.isEditable = false
        output.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        output.textColor = NSColor(calibratedWhite: 0.88, alpha: 1)
        output.backgroundColor = NSColor(calibratedWhite: 0.045, alpha: 1)
        output.string = "Selecciona una herramienta. Los análisis se ejecutan localmente.\n"
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.documentView = output

        let header = NSStackView(views: [title, subtitle, buttonGrid, status])
        header.orientation = .vertical
        header.alignment = .leading
        header.spacing = 8
        let stack = NSStackView(views: [header, scroll])
        stack.orientation = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            buttonGrid.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    private func chooseFile(title: String, types: [String]? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        if let types { panel.allowedContentTypes = types.compactMap { UTType(filenameExtension: $0) } }
        return panel.runModal() == .OK ? panel.url : nil
    }

    private func display(_ text: String, state: String = "● COMPLETADO") {
        output.string = text
        output.scrollToBeginningOfDocument(nil)
        status.stringValue = state
        status.textColor = state.contains("ERROR") ? .systemRed : .systemGreen
    }

    private func runBackground(_ work: @escaping () throws -> String) {
        guard actionButtons.allSatisfy(\.isEnabled) else {
            display("Ya hay una herramienta trabajando. Espera a que termine antes de iniciar otra.", state: "● OCUPADO")
            return
        }
        actionButtons.forEach { $0.isEnabled = false }
        status.stringValue = "● ANALIZANDO"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let result = try work()
                DispatchQueue.main.async { self?.actionButtons.forEach { $0.isEnabled = true }; self?.display(result) }
            } catch {
                DispatchQueue.main.async { self?.actionButtons.forEach { $0.isEnabled = true }; self?.display(error.localizedDescription, state: "● ERROR") }
            }
        }
    }

    @objc private func hashFile() {
        guard let file = chooseFile(title: "Selecciona un archivo para calcular hashes") else { return }
        runBackground {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw NSError(domain: "ForensicToolkit", code: 10, userInfo: [NSLocalizedDescriptionKey: "La fuente debe ser un archivo regular, no un enlace simbólico."])
            }
            let before = try FileManager.default.attributesOfItem(atPath: file.path)
            let handle = try FileHandle(forReadingFrom: file)
            defer { try? handle.close() }
            var sha = SHA256()
            var crc: UInt32 = 0
            var size = 0
            while true {
                let data = try handle.read(upToCount: 1024 * 1024) ?? Data()
                if data.isEmpty { break }
                sha.update(data: data)
                crc = Self.crc32(data, seed: crc)
                size += data.count
            }
            let after = try FileManager.default.attributesOfItem(atPath: file.path)
            guard before[.systemFileNumber] as? NSNumber == after[.systemFileNumber] as? NSNumber,
                  before[.size] as? NSNumber == after[.size] as? NSNumber,
                  before[.modificationDate] as? NSDate == after[.modificationDate] as? NSDate else {
                throw NSError(domain: "ForensicToolkit", code: 11, userInfo: [NSLocalizedDescriptionKey: "El archivo cambió durante el cálculo; el hash fue descartado."])
            }
            return "ARCHIVO: \(file.path)\nTAMAÑO: \(size) bytes\nSHA-256: \(sha.finalize().map { String(format: "%02x", $0) }.joined())\nCRC32: \(String(format: "%08x", crc))"
        }
    }

    @objc private func hexViewer() {
        guard let file = chooseFile(title: "Selecciona un archivo para vista hexadecimal") else { return }
        runBackground {
            let handle = try FileHandle(forReadingFrom: file)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: 1024 * 1024) ?? Data()
            var lines: [String] = []
            for offset in stride(from: 0, to: data.count, by: 16) {
                let chunk = data[offset..<min(offset + 16, data.count)]
                let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ").padding(toLength: 47, withPad: " ", startingAt: 0)
                let ascii = chunk.map { $0 >= 32 && $0 < 127 ? Character(UnicodeScalar($0)) : "." }.map(String.init).joined()
                lines.append(String(format: "%08x  %@  |%@|", offset, hex, ascii))
            }
            return "\(file.path)\nPrimeros \(data.count) bytes\n\n" + lines.joined(separator: "\n")
        }
    }

    @objc private func convertTimestamp() {
        let alert = NSAlert()
        alert.messageText = "Conversor forense de timestamps"
        alert.informativeText = "Introduce un valor numérico"
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Convertir")
        alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn, let value = Double(field.stringValue) else { return }
        let unixSeconds = value > 10_000_000_000 ? value / 1000 : value
        let formats: [(String, Date)] = [
            ("Unix (s/ms)", Date(timeIntervalSince1970: unixSeconds)),
            ("Cocoa desde 2001", Date(timeIntervalSinceReferenceDate: value)),
            ("WebKit microsegundos desde 1601", Date(timeIntervalSince1970: value / 1_000_000 - 11_644_473_600)),
        ]
        let formatter = ISO8601DateFormatter()
        display(formats.map { "\($0.0): \(formatter.string(from: $0.1))" }.joined(separator: "\n"))
    }

    @objc private func sqliteAudit() { runEngineFileTool(title: "Selecciona SQLite", types: ["db", "sqlite", "sqlite3"], command: "sqlite-audit") }
    @objc private func apkAudit() { runEngineFileTool(title: "Selecciona APK", types: ["apk"], command: "apk-audit") }

    private func runEngineFileTool(title: String, types: [String], command: String) {
        guard let source = chooseFile(title: title, types: types) else { return }
        runBackground { try self.runEngine(command: command, source: source) }
    }

    @objc private func androidInventory() {
        runBackground { try self.runEngine(command: "android-inventory", source: nil) }
    }

    @objc private func androidCommunications() {
        runBackground { try self.runEngine(command: "android-communications", source: nil) }
    }

    @objc private func chromeHistory() {
        guard let source = chooseFile(title: "Selecciona la base History de Google Chrome") else { return }
        runBackground { try self.runEngine(command: "chrome-history", source: source) }
    }

    private func runEngine(command: String, source: URL?) throws -> String {
        if reportsRoot.isFileURL && reportsRoot.resolvingSymlinksInPath() != reportsRoot.standardizedFileURL {
            throw NSError(domain: "ForensicToolkit", code: 12, userInfo: [NSLocalizedDescriptionKey: "La carpeta de reportes contiene un enlace simbólico no permitido."])
        }
        try FileManager.default.createDirectory(at: reportsRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let directory = reportsRoot.appendingPathComponent("Toolkit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let report = directory.appendingPathComponent("\(command).json")
        let process = Process()
        process.executableURL = python
        if let source {
            let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw NSError(domain: "ForensicToolkit", code: 13, userInfo: [NSLocalizedDescriptionKey: "La fuente debe ser un archivo regular y no un enlace simbólico."])
            }
            process.arguments = [engine.path, command, source.path, report.path]
        } else {
            process.arguments = [engine.path, command, report.path]
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "ForensicToolkit", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: String(data: data, encoding: .utf8) ?? "Fallo del motor"])
        }
        return String(data: try Data(contentsOf: report), encoding: .utf8) ?? "Reporte: \(report.path)"
    }

    @objc private func runOCR() {
        guard let image = chooseFile(title: "Selecciona una imagen para OCR", types: ["jpg", "jpeg", "png", "heic", "webp"]) else { return }
        runBackground {
            let values = try image.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw NSError(domain: "ForensicToolkit", code: 14, userInfo: [NSLocalizedDescriptionKey: "La imagen debe ser un archivo regular y no un enlace simbólico."])
            }
            guard (values.fileSize ?? 0) <= 250 * 1024 * 1024 else {
                throw NSError(domain: "ForensicToolkit", code: 15, userInfo: [NSLocalizedDescriptionKey: "La imagen supera 250 MB; crea una copia de trabajo reducida antes del OCR para evitar agotar la memoria."])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.usesLanguageCorrection = true
            let handler = VNImageRequestHandler(url: image)
            try handler.perform([request])
            let observations = request.results ?? []
            let text = observations.compactMap { $0.topCandidates(1).first?.string }.joined(separator: "\n")
            return "OCR LOCAL: \(image.path)\n\n" + (text.isEmpty ? "No se reconoció texto." : text)
        }
    }

    private static func crc32(_ data: Data, seed: UInt32) -> UInt32 {
        var crc = seed ^ 0xffffffff
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ (0xedb88320 & UInt32(bitPattern: -Int32(crc & 1))) }
        }
        return crc ^ 0xffffffff
    }
}
