import AppKit
import CryptoKit
import Foundation
import UniformTypeIdentifiers
import WebKit

final class GradientView: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSGradient(
            colors: [
                NSColor(calibratedRed: 0.035, green: 0.055, blue: 0.075, alpha: 1),
                NSColor(calibratedRed: 0.055, green: 0.125, blue: 0.090, alpha: 1),
                NSColor(calibratedRed: 0.025, green: 0.070, blue: 0.048, alpha: 1),
            ]
        )?.draw(in: bounds, angle: -35)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    private var window: NSWindow!
    private var statusLabel: NSTextField!
    private var summaryView: NSTextView!
    private var galleryWebView: WKWebView!
    private var runDemoButton: NSButton!
    private var acquireButton: NSButton!
    private var adbButton: NSButton!
    private var loadReportButton: NSButton!
    private var openFolderButton: NSButton!
    private var cancelButton: NSButton!
    private var whatsAppAnalyzeButton: NSButton!
    private var carvingButton: NSButton!
    private var toolkitButton: NSButton!
    private var progressIndicator: NSProgressIndicator!
    private var splitView: NSSplitView!
    private var summaryBox: NSBox!
    private var artifactsBox: NSBox!
    private var currentCaseDirectory: URL?
    private var currentProcess: Process?
    private var currentOperationCleansPartials = false
    private var whatsAppBackupPath: URL?
    private var whatsAppKeyPath: URL?
    private var whatsAppDecryptedPath: URL?
    private var toolkitController: ForensicToolkitController?
    private var navigationButtons: [NSButton] = []
    private let sealLock = NSLock()
    private let auditLock = NSLock()

    private let forensicGreen = NSColor(calibratedRed: 0.20, green: 0.95, blue: 0.48, alpha: 1.0)
    private let forensicCyan = NSColor(calibratedRed: 0.20, green: 0.82, blue: 0.95, alpha: 1.0)
    private let consoleBackground = NSColor(calibratedWhite: 0.055, alpha: 1.0)
    private let panelBackground = NSColor(calibratedRed: 0.955, green: 0.970, blue: 0.962, alpha: 1.0)

    func applicationDidFinishLaunching(_ notification: Notification) {
        // A signed .app must never be mutated by Python bytecode caches at runtime.
        setenv("PYTHONDONTWRITEBYTECODE", "1", 1)
        _ = casesRoot()
        buildMenu()
        buildWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let process = currentProcess, process.isRunning else { return .terminateNow }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Hay una operación forense en curso"
        alert.informativeText = "Si sales ahora, el motor recibirá una cancelación controlada. Los archivos terminados se conservan y los parciales no se consideran evidencia final."
        alert.addButton(withTitle: "Cancelar operación y salir")
        alert.addButton(withTitle: "Seguir trabajando")
        guard alert.runModal() == .alertFirstButtonReturn else { return .terminateCancel }
        process.terminate()
        DispatchQueue.global(qos: .userInitiated).async {
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            DispatchQueue.main.async { sender.reply(toApplicationShouldTerminate: true) }
        }
        return .terminateLater
    }

    private func buildMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Acerca de Forensic Mobile Lab", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Salir", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let fileItem = NSMenuItem()
        mainMenu.addItem(fileItem)
        let fileMenu = NSMenu(title: "Archivo")
        fileMenu.addItem(withTitle: "Abrir reporte…", action: #selector(selectReport), keyEquivalent: "o")
        fileMenu.addItem(withTitle: "Gestión de casos", action: #selector(showCaseManager), keyEquivalent: "1")
        fileMenu.addItem(NSMenuItem.separator())
        fileMenu.addItem(withTitle: "Exportar expediente…", action: #selector(exportCurrentCase), keyEquivalent: "e")
        fileMenu.addItem(withTitle: "Imprimir / PDF…", action: #selector(printReport), keyEquivalent: "p")
        fileItem.submenu = fileMenu

        let toolsItem = NSMenuItem()
        mainMenu.addItem(toolsItem)
        let toolsMenu = NSMenu(title: "Herramientas")
        toolsMenu.addItem(withTitle: "Diagnóstico del sistema", action: #selector(showSystemDiagnostics), keyEquivalent: "d")
        toolsMenu.addItem(withTitle: "Verificar integridad", action: #selector(verifyIntegrity), keyEquivalent: "v")
        toolsMenu.addItem(withTitle: "Kit Forense", action: #selector(showForensicToolkit), keyEquivalent: "k")
        toolsItem.submenu = toolsMenu

        let helpItem = NSMenuItem()
        mainMenu.addItem(helpItem)
        let helpMenu = NSMenu(title: "Ayuda")
        helpMenu.addItem(withTitle: "Seguridad y verificación", action: #selector(showSecurityGuide), keyEquivalent: "?")
        helpMenu.addItem(withTitle: "Notas de Forensic Mobile Lab 3.2", action: #selector(showReleaseNotes), keyEquivalent: "")
        helpMenu.addItem(withTitle: "Informe de auditoría 3.2", action: #selector(showAuditReport), keyEquivalent: "")
        helpItem.submenu = helpMenu
        NSApp.mainMenu = mainMenu
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1280, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Forensic Mobile Lab — Estación forense autorizada"
        window.appearance = NSAppearance(named: .darkAqua)
        window.backgroundColor = consoleBackground
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.styleMask.insert(.fullSizeContentView)
        window.toolbarStyle = .unifiedCompact
        window.center()
        window.minSize = NSSize(width: 1040, height: 640)

        let root = GradientView()
        root.translatesAutoresizingMaskIntoConstraints = false
        root.wantsLayer = true
        window.contentView = root

        let sidebar = NSVisualEffectView()
        sidebar.translatesAutoresizingMaskIntoConstraints = false
        sidebar.material = .sidebar
        sidebar.blendingMode = .withinWindow
        sidebar.state = .active

        let contentArea = NSView()
        contentArea.translatesAutoresizingMaskIntoConstraints = false

        let sidebarLogo = NSTextField(labelWithString: "FORENSIC\nMOBILE LAB")
        sidebarLogo.font = .systemFont(ofSize: 18, weight: .bold)
        sidebarLogo.textColor = .white
        sidebarLogo.alignment = .center

        let homeNav = makeSidebarButton("Centro de adquisición", symbol: "house.fill", action: #selector(showAcquisitionCenter))
        let toolsNav = makeSidebarButton("Centro de herramientas", symbol: "square.grid.2x2.fill", action: #selector(showToolsCenter))
        let diagnosticsNav = makeSidebarButton("Diagnóstico del sistema", symbol: "stethoscope", action: #selector(showSystemDiagnostics))
        let casesNav = makeSidebarButton("Gestión de casos", symbol: "archivebox.fill", action: #selector(showCaseManager))
        let deviceNav = makeSidebarButton("Identidad del dispositivo", symbol: "iphone", action: #selector(showDeviceDashboard))
        let galleryNav = makeSidebarButton("Galería & Recovery", symbol: "photo.on.rectangle.angled", action: #selector(showGalleryDashboard))
        let multimediaNav = makeSidebarButton("Multimedia Recovery", symbol: "play.rectangle.on.rectangle.fill", action: #selector(showMultimediaDashboard))
        let sqlNav = makeSidebarButton("Mensajes SQL", symbol: "message.fill", action: #selector(showSQLDashboard))
        let fileTreeNav = makeSidebarButton("Sistema de archivos", symbol: "folder.fill", action: #selector(showFileTreeDashboard))
        let timelineNav = makeSidebarButton("Timeline unificado", symbol: "clock.fill", action: #selector(showTimelineDashboard))
        let linksNav = makeSidebarButton("Smart Linking", symbol: "link", action: #selector(showLinksDashboard))
        let reportNav = makeSidebarButton("Reporte Final", symbol: "doc.text.magnifyingglass", action: #selector(showReportDashboard))
        let auditNav = makeSidebarButton("Cadena de custodia", symbol: "list.bullet.clipboard.fill", action: #selector(showAuditTrail))
        let verifyNav = makeSidebarButton("Verificar integridad", symbol: "checkmark.shield.fill", action: #selector(verifyIntegrity))
        let protectNav = makeSidebarButton("Proteger originales", symbol: "lock.shield.fill", action: #selector(protectCurrentEvidence))
        let backupNav = makeSidebarButton("Respaldar expediente", symbol: "externaldrive.fill.badge.checkmark", action: #selector(backupCurrentCase))
        let exportNav = makeSidebarButton("Exportar expediente", symbol: "square.and.arrow.up.fill", action: #selector(exportCurrentCase))
        let secureExportNav = makeSidebarButton("Exportación cifrada", symbol: "lock.doc.fill", action: #selector(exportEncryptedCase))
        let compareNav = makeSidebarButton("Comparar adquisiciones", symbol: "arrow.left.arrow.right", action: #selector(compareCases))
        let pdfNav = makeSidebarButton("Imprimir / PDF", symbol: "printer.fill", action: #selector(printReport))
        let searchNav = makeSidebarButton("Búsqueda FTS5", symbol: "magnifyingglass", action: #selector(searchCaseIndex))
        let redactNav = makeSidebarButton("Reporte redactado", symbol: "eye.slash.fill", action: #selector(exportRedactedReport))
        let intelligenceNav = makeSidebarButton("Inteligencia avanzada", symbol: "brain.head.profile", action: #selector(runAdvancedIntelligence))
        let workstationNav = makeSidebarButton("Discos / iPhone", symbol: "externaldrive.connected.to.line.below", action: #selector(showWorkstationCenter))
        let sidebarFooter = NSTextField(labelWithString: "ADB • LOGICAL\nRECOVERY MODE")
        sidebarFooter.font = .monospacedSystemFont(ofSize: 10, weight: .medium)
        sidebarFooter.textColor = .secondaryLabelColor
        sidebarFooter.alignment = .center
        navigationButtons = [homeNav, toolsNav, diagnosticsNav, casesNav, deviceNav, workstationNav, galleryNav, multimediaNav, sqlNav, searchNav, intelligenceNav, fileTreeNav, timelineNav, linksNav, reportNav, auditNav, verifyNav, protectNav, backupNav, compareNav, redactNav, exportNav, secureExportNav, pdfNav]

        let sidebarStack = NSStackView(views: [sidebarLogo, homeNav, toolsNav, diagnosticsNav, casesNav, deviceNav, workstationNav, galleryNav, multimediaNav, sqlNav, searchNav, intelligenceNav, fileTreeNav, timelineNav, linksNav, reportNav, auditNav, verifyNav, protectNav, backupNav, compareNav, redactNav, exportNav, secureExportNav, pdfNav, sidebarFooter])
        sidebarStack.translatesAutoresizingMaskIntoConstraints = false
        sidebarStack.orientation = .vertical
        sidebarStack.alignment = .centerX
        sidebarStack.spacing = 7
        let sidebarDocument = NSView()
        sidebarDocument.translatesAutoresizingMaskIntoConstraints = false
        sidebarDocument.addSubview(sidebarStack)
        let sidebarScroll = NSScrollView()
        sidebarScroll.translatesAutoresizingMaskIntoConstraints = false
        sidebarScroll.drawsBackground = false
        sidebarScroll.hasVerticalScroller = true
        sidebarScroll.autohidesScrollers = true
        sidebarScroll.documentView = sidebarDocument
        sidebar.addSubview(sidebarScroll)

        let title = NSTextField(labelWithString: "FORENSIC MOBILE LAB")
        title.font = .systemFont(ofSize: 30, weight: .bold)
        title.textColor = .white

        let subtitle = NSTextField(labelWithString: "ADQUISICIÓN AUTORIZADA  •  INTEGRIDAD  •  ANDROID / IPHONE / DISCOS")
        subtitle.font = .systemFont(ofSize: 12, weight: .semibold)
        subtitle.textColor = forensicCyan

        runDemoButton = NSButton(title: "Ejecutar demostración", target: self, action: #selector(runDemo))
        runDemoButton.bezelStyle = .rounded

        acquireButton = NSButton(title: "Seleccionar dispositivo simulado…", target: self, action: #selector(selectDevice))
        acquireButton.bezelStyle = .rounded

        adbButton = NSButton(title: "Conectar Android por ADB", target: self, action: #selector(connectADB))
        adbButton.bezelStyle = .rounded

        loadReportButton = NSButton(title: "Abrir reporte…", target: self, action: #selector(selectReport))
        loadReportButton.bezelStyle = .rounded

        openFolderButton = NSButton(title: "Abrir carpeta del caso", target: self, action: #selector(openCaseFolder))
        openFolderButton.bezelStyle = .rounded
        openFolderButton.isEnabled = false


        cancelButton = NSButton(title: "Cancelar", target: self, action: #selector(cancelAcquisition))
        cancelButton.bezelStyle = .rounded
        cancelButton.contentTintColor = .systemRed
        cancelButton.isHidden = true

        whatsAppAnalyzeButton = NSButton(title: "Analizar WhatsApp", target: self, action: #selector(autoScanWhatsApp))
        whatsAppAnalyzeButton.bezelStyle = .rounded
        whatsAppAnalyzeButton.toolTip = "Busca automáticamente el backup y su clave; si ya están cargados, inicia el análisis"
        carvingButton = NSButton(title: "🔍 Escanear fotos por firmas", target: self, action: #selector(startADBFileCarving))
        carvingButton.bezelStyle = .rounded
        carvingButton.toolTip = "Busca JPEG, PNG, GIF y WebP; registra procedencia, estabilidad y hashes mediante ADB"
        toolkitButton = NSButton(title: "Kit Forense", target: self, action: #selector(showForensicToolkit))
        toolkitButton.bezelStyle = .rounded
        toolkitButton.toolTip = "Hashes, hexadecimal, timestamps, SQLite/WAL, APK, OCR e inventario Android"

        for button in [runDemoButton!, acquireButton!, adbButton!, loadReportButton!, openFolderButton!, cancelButton!, whatsAppAnalyzeButton!, carvingButton!, toolkitButton!] {
            button.font = .systemFont(ofSize: 12, weight: .semibold)
            button.contentTintColor = forensicCyan
        }

        progressIndicator = NSProgressIndicator()
        progressIndicator.style = .spinning
        progressIndicator.controlSize = .small
        progressIndicator.isIndeterminate = true
        progressIndicator.isDisplayedWhenStopped = false

        statusLabel = NSTextField(labelWithString: "● SYSTEM READY")
        statusLabel.textColor = forensicGreen
        statusLabel.font = .systemFont(ofSize: 11, weight: .bold)

        let buttonRow = NSStackView(views: [runDemoButton, acquireButton, adbButton, loadReportButton, openFolderButton, cancelButton, progressIndicator, statusLabel])
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 10
        buttonRow.alignment = .centerY
        buttonRow.setHuggingPriority(.defaultLow, for: .horizontal)

        let whatsAppRow = NSStackView(views: [whatsAppAnalyzeButton, carvingButton, toolkitButton])
        whatsAppRow.orientation = .horizontal
        whatsAppRow.spacing = 10
        whatsAppRow.alignment = .centerY

        summaryView = makeTextView()
        summaryView.string = welcomeText
        let webConfiguration = WKWebViewConfiguration()
        webConfiguration.websiteDataStore = .nonPersistent()
        webConfiguration.mediaTypesRequiringUserActionForPlayback = .all
        webConfiguration.allowsAirPlayForMediaPlayback = false
        let networkBlockRules = """
        [{"trigger":{"url-filter":"^https?://"},"action":{"type":"block"}}]
        """
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "ForensicMobileLab.BlockNetwork.v1",
            encodedContentRuleList: networkBlockRules
        ) { ruleList, _ in
            if let ruleList { webConfiguration.userContentController.add(ruleList) }
        }
        galleryWebView = WKWebView(frame: .zero, configuration: webConfiguration)
        galleryWebView.translatesAutoresizingMaskIntoConstraints = false
        galleryWebView.navigationDelegate = self
        showAcquisitionCenter()

        let summaryScroll = makeScrollView(document: summaryView)

        summaryBox = makeBox(title: " DEVICE STATUS / CASE SUMMARY ", content: summaryScroll, color: forensicGreen)
        artifactsBox = makeBox(title: " ACQUISITION WORKSPACE / FORENSIC RESULTS ", content: galleryWebView, color: forensicCyan)

        splitView = NSSplitView()
        splitView.translatesAutoresizingMaskIntoConstraints = false
        splitView.isVertical = true
        splitView.dividerStyle = .thin
        splitView.addArrangedSubview(summaryBox)
        splitView.addArrangedSubview(artifactsBox)

        let header = NSStackView(views: [title, subtitle, buttonRow, whatsAppRow])
        header.orientation = .vertical
        header.alignment = .leading
        header.spacing = 5
        header.translatesAutoresizingMaskIntoConstraints = false

        root.addSubview(sidebar)
        root.addSubview(contentArea)
        contentArea.addSubview(header)
        contentArea.addSubview(splitView)

        NSLayoutConstraint.activate([
            sidebar.topAnchor.constraint(equalTo: root.topAnchor),
            sidebar.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            sidebar.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            sidebar.widthAnchor.constraint(equalToConstant: 232),
            sidebarScroll.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 22),
            sidebarScroll.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 8),
            sidebarScroll.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -8),
            sidebarScroll.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -12),
            sidebarDocument.widthAnchor.constraint(equalTo: sidebarScroll.contentView.widthAnchor),
            sidebarStack.topAnchor.constraint(equalTo: sidebarDocument.topAnchor, constant: 6),
            sidebarStack.leadingAnchor.constraint(equalTo: sidebarDocument.leadingAnchor, constant: 6),
            sidebarStack.trailingAnchor.constraint(equalTo: sidebarDocument.trailingAnchor, constant: -6),
            sidebarStack.bottomAnchor.constraint(equalTo: sidebarDocument.bottomAnchor, constant: -12),
            homeNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            toolsNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            diagnosticsNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            casesNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            deviceNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            galleryNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            multimediaNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            sqlNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            fileTreeNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            timelineNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            linksNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            reportNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            verifyNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            protectNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            backupNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            exportNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            secureExportNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            compareNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            pdfNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            searchNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            redactNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            intelligenceNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            workstationNav.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            contentArea.topAnchor.constraint(equalTo: root.topAnchor),
            contentArea.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            contentArea.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            contentArea.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            header.topAnchor.constraint(equalTo: contentArea.topAnchor, constant: 22),
            header.leadingAnchor.constraint(equalTo: contentArea.leadingAnchor, constant: 24),
            header.trailingAnchor.constraint(equalTo: contentArea.trailingAnchor, constant: -24),
            buttonRow.widthAnchor.constraint(equalTo: header.widthAnchor),
            splitView.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 18),
            splitView.leadingAnchor.constraint(equalTo: contentArea.leadingAnchor, constant: 24),
            splitView.trailingAnchor.constraint(equalTo: contentArea.trailingAnchor, constant: -24),
            splitView.bottomAnchor.constraint(equalTo: contentArea.bottomAnchor, constant: -24),
            summaryBox.widthAnchor.constraint(greaterThanOrEqualToConstant: 310),
            artifactsBox.widthAnchor.constraint(greaterThanOrEqualToConstant: 420)
        ])
        summaryBox.isHidden = true
    }

    private var welcomeText: String {
        """
        ╔══════════════════════════════════════════════╗
        ║          AUTHORIZED FORENSIC CONSOLE         ║
        ╚══════════════════════════════════════════════╝

        [DEMO] Ejecutar demostración crea SMS, WhatsApp y llamadas simuladas.
        [FILE] Seleccionar dispositivo analiza una carpeta de laboratorio.
        [ADB ] Conectar Android usa un equipo que ya autorizó esta Mac.
        [HASH] Cada archivo se valida mediante CRC32 y SHA-256.
        [SAFE] Equipos bloqueados o no autorizados son rechazados.

        No desbloquea equipos, evade permisos ni explota interfaces ADB/JTAG.
        """
    }

    private func makeTextView() -> NSTextView {
        let view = NSTextView()
        view.isEditable = false
        view.isSelectable = true
        view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        view.textColor = NSColor(calibratedRed: 0.07, green: 0.20, blue: 0.14, alpha: 1)
        view.backgroundColor = panelBackground
        view.textContainerInset = NSSize(width: 12, height: 12)
        view.autoresizingMask = [.width]
        return view
    }

    private func makeScrollView(document: NSView) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.borderType = .noBorder
        scroll.documentView = document
        return scroll
    }

    private func makeBox(title: String, content: NSView, color: NSColor) -> NSBox {
        let box = NSBox()
        box.translatesAutoresizingMaskIntoConstraints = false
        box.title = title
        box.titlePosition = .atTop
        box.boxType = .custom
        box.borderWidth = 1
        box.cornerRadius = 12
        box.borderColor = color.withAlphaComponent(0.45)
        box.fillColor = panelBackground.withAlphaComponent(0.88)
        box.titleFont = .systemFont(ofSize: 11, weight: .bold)
        if let titleCell = box.titleCell as? NSTextFieldCell {
            titleCell.textColor = color
        }
        content.translatesAutoresizingMaskIntoConstraints = false
        if let container = box.contentView {
            container.addSubview(content)
            NSLayoutConstraint.activate([
                content.topAnchor.constraint(equalTo: container.topAnchor, constant: 2),
                content.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 2),
                content.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -2),
                content.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -2),
            ])
        }
        return box
    }

    private func makeSidebarButton(_ title: String, symbol: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .recessed
        button.font = .systemFont(ofSize: 13, weight: .semibold)
        button.alignment = .left
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: title)
        button.imagePosition = .imageLeading
        button.imageScaling = .scaleProportionallyDown
        button.contentTintColor = forensicCyan
        button.toolTip = title
        button.setAccessibilityLabel(title)
        return button
    }

    @objc private func showDeviceDashboard() {
        summaryBox.isHidden = false
        artifactsBox.isHidden = true
        window.makeFirstResponder(summaryView)
    }

    @objc private func showAcquisitionCenter() {
        if summaryBox != nil {
            summaryBox.isHidden = true
            artifactsBox.isHidden = false
        }
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>
        :root{color-scheme:dark}*{box-sizing:border-box}html,body{width:100%;min-width:0}body{margin:0;padding:22px;overflow-x:hidden;background:radial-gradient(circle at 15% 0,#17333c 0,#0b151c 45%,#070b10 100%);color:#eaf7f8;font:13px -apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif}
        header{padding:8px 2px 20px}h1{font-size:28px;margin:0 0 7px}header p{color:#91aab1;margin:0}.steps{display:flex;align-items:center;gap:8px;margin:4px 0 22px}.step{flex:1;padding:10px;border-radius:10px;background:#14232b;color:#7f979e;text-align:center;font-size:11px;font-weight:800}.step.on{background:#17453e;color:#73f2b5;border:1px solid #3ea982}.arrow{color:#4f6972}.grid{display:grid;grid-template-columns:repeat(2,minmax(240px,1fr));gap:14px;width:100%}.card{position:relative;width:100%;min-width:0;padding:18px;border-radius:16px;background:linear-gradient(145deg,#1a2c35,#101a21);border:1px solid #31505d;box-shadow:0 14px 30px #0005;min-height:165px}.card.active{border-color:#45cde9}.card.recovery{border-color:#d85f66}.card.disabled{opacity:.62;border-color:#655d52}.icon{font-size:26px}.card h2{font-size:16px;margin:10px 0 7px;overflow-wrap:anywhere}.card p{color:#9db0b5;line-height:1.45;margin:0 0 12px;overflow-wrap:anywhere}.status{display:inline-block;max-width:100%;border-radius:999px;padding:4px 9px;background:#163b39;color:#69efb0;font-size:10px;font-weight:800;letter-spacing:.06em;white-space:normal}.limited{background:#4a2529;color:#ff9ca1}.blocked{background:#413a29;color:#f1cb70}.launch{display:inline-block;margin-top:12px;padding:8px 12px;border-radius:9px;background:#31bddd;color:#061216;text-decoration:none;font-weight:800}.launch.demo{background:#48d98b}.card:hover{transform:translateY(-2px);border-color:#72e3f5}.sources{margin-top:18px;padding:16px;border:1px solid #283e47;border-radius:14px;background:#0e171dcc}.sources b{color:#59d9f5}.sources span{display:inline-block;margin:9px 7px 0 0;padding:5px 9px;border-radius:8px;background:#18272f;color:#b8cbd0}@media(max-width:720px){.grid{grid-template-columns:1fr}.steps{align-items:stretch}.arrow{display:none}.step{padding:8px 3px;font-size:9px}}
        </style></head><body><header><h1>Centro de adquisición móvil</h1><p>Flujos autorizados disponibles y límites técnicos del dispositivo conectado.</p></header>
        <nav class="steps"><span class="step on">1 · DISPOSITIVO</span><span class="arrow">›</span><span class="step">2 · MÉTODO</span><span class="arrow">›</span><span class="step">3 · CONTENIDO</span><span class="arrow">›</span><span class="step">4 · ADQUISICIÓN</span><span class="arrow">›</span><span class="step">5 · RESULTADOS</span></nav>
        <section class="grid">
        <article class="card active"><div class="icon">▤</div><h2>Extracción lógica completa</h2><p>Galería visible, almacenamiento compartido, metadatos y bases SQLite accesibles.</p><span class="status">OPERATIVO · ADB</span><br><a class="launch" href="forensic://adb">DETECTAR ANDROID</a></article>
        <article class="card active"><div class="icon">▱</div><h2>Carpeta de laboratorio</h2><p>Analiza una estructura de archivos aportada sin conectar un teléfono.</p><span class="status">OPERATIVO · ARCHIVOS</span><br><a class="launch" href="forensic://folder">SELECCIONAR CARPETA</a></article>
        <article class="card recovery"><div class="icon">◈</div><h2>Galería y recuperación lógica</h2><p>DCIM/Pictures más cachés, miniaturas y papelera visibles; cada archivo conserva SHA-256 y CRC32.</p><span class="status limited">[!REC] RECOVERY MODE</span><br><a class="launch" href="forensic://adb">INICIAR CON ADB</a></article>
        <article class="card active"><div class="icon">☷</div><h2>Demostración verificable</h2><p>Genera un caso local de muestra para conocer galerías, SQL, timeline y reporte.</p><span class="status">SIN TELÉFONO</span><br><a class="launch demo" href="forensic://demo">EJECUTAR DEMO</a></article>
        <article class="card disabled"><div class="icon">▣</div><h2>Captura de pantalla</h2><p>La captura puntual requiere que Android autorice screencap; no forma parte de la adquisición automática.</p><span class="status blocked">NO ACTIVADA</span></article>
        <article class="card disabled"><div class="icon">⬡</div><h2>Extracción física / JTAG</h2><p>Una imagen física, memoria sin asignar o bypass de bloqueo requiere root, bootloader o hardware especializado.</p><span class="status blocked">REQUIERE ROOT / HARDWARE</span></article>
        </section><section class="sources"><b>Fuentes seleccionadas</b><br><span>Phone · Content</span><span>Phone · Contacts</span><span>DCIM</span><span>Pictures</span><span>WhatsApp Media</span><span>SQLite</span><span>Hidden caches</span></section>
        </body></html>
        """
        galleryWebView?.loadHTMLString(html, baseURL: nil)
    }

    @objc private func showCaseManager() {
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        let manager = FileManager.default
        let directories = (try? manager.contentsOfDirectory(
            at: casesRoot(),
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        let cases = directories.filter {
            manager.fileExists(atPath: $0.appendingPathComponent("reports/forensic_report.json").path)
            || manager.fileExists(atPath: $0.appendingPathComponent("case/reports/forensic_report.json").path)
        }.sorted { left, right in
            let l = (try? left.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let r = (try? right.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return l > r
        }
        let cards = cases.map { directory -> String in
            let actual = manager.fileExists(atPath: directory.appendingPathComponent("reports/forensic_report.json").path) ? directory : directory.appendingPathComponent("case")
            let encoded = actual.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            let modified = (try? directory.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)?.formatted() ?? "—"
            return "<article><b>\(htmlEscape(directory.lastPathComponent))</b><span>\(htmlEscape(modified))</span><a href='forensic://case?path=\(encoded)'>ABRIR EXPEDIENTE</a></article>"
        }.joined()
        let empty = cases.isEmpty ? "<p class='empty'>Todavía no existen expedientes guardados.</p>" : ""
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#091117;color:#e6f3f4;font:14px -apple-system}h1{font-size:28px}header p,article span{color:#8ea4aa}main{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}article{padding:18px;border:1px solid #31515d;border-radius:14px;background:#12212a}article b,article span{display:block;margin-bottom:10px}a{display:inline-block;padding:8px 11px;background:#35c2df;color:#061216;border-radius:8px;text-decoration:none;font-weight:800}.empty{padding:40px;border:1px dashed #3b555e;border-radius:14px;text-align:center}</style></head><body><header><h1>Gestión de casos</h1><p>Expedientes locales ordenados por actividad reciente.</p></header><main>\(cards)</main>\(empty)</body></html>
        """
        galleryWebView.loadHTMLString(html, baseURL: nil)
    }

    @objc private func showToolsCenter() {
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        let modules = [
            ("Adquisición lógica ADB", "USB autorizado · perfiles · checkpoints", "OPERATIVO", "ok"),
            ("Galería y multimedia", "Fotos, video, audio, EXIF, GPS y miniaturas", "OPERATIVO", "ok"),
            ("Comunicaciones SQLite", "SMS, WhatsApp, llamadas y contactos", "OPERATIVO", "ok"),
            ("Índice FTS5", "Búsqueda en archivos, mensajes y metadatos", "OPERATIVO", "ok"),
            ("Calidad de evidencia", "Cobertura, advertencias, EXIF y archivos vacíos", "OPERATIVO", "ok"),
            ("Duplicados", "SHA-256 exacto y dHash visual", "OPERATIVO", "ok"),
            ("Cadena de custodia", "Eventos encadenados criptográficamente", "OPERATIVO", "ok"),
            ("Exportaciones", "ZIP, JSON, CSV, HTML e impresión PDF", "OPERATIVO", "ok"),
            ("Runtime autocontenido", "Núcleo y ADB universales; conector iPhone local optimizado para Apple Silicon", "OPERATIVO · NÚCLEO UNIVERSAL", "ok"),
            ("Carving con procedencia", "Streaming temporal, hash del contenedor y control de estabilidad", "OPERATIVO", "ok"),
            ("Inteligencia avanzada", "Timeline, entidades, geografía, conversaciones y RAG local con citas", "OPERATIVO", "ok"),
            ("iOS y maestros físicos", "Ingreso autorizado de backups/imágenes aportadas; sin bypass", "OPERATIVO · INGESTA", "ok"),
            ("Backup automático de iPhone", "USB, confianza, progreso, checkpoint y catálogo automático", "APPLE SILICON · REQUIERE IPHONE", "ok"),
            ("OCR y transcripción", "Adaptadores locales; conserva original y procedencia", "OPERATIVO · SEGÚN MOTOR LOCAL", "ok"),
            ("Extensiones aisladas", "Descriptores permitidos y analizadores en procesos separados", "OPERATIVO", "ok"),
            ("Paquete validador portátil", "Manifiesto SHA-256 y verificador sin depender de la app", "OPERATIVO", "ok"),
            ("Vista previa universal", "PDF, imágenes, audio, video y formatos compatibles dentro del catálogo", "OPERATIVO", "ok"),
            ("Imágenes RAW/DD", "Lectura por bloques, checkpoint, reanudación y SHA-256", "OPERATIVO · SELECCIÓN EXPLÍCITA", "ok"),
            ("Archivos disfrazados", "Compara extensión, MIME y firma binaria real", "OPERATIVO", "ok"),
            ("Mapa y relaciones", "GeoJSON y grafo de entidades con procedencia", "OPERATIVO", "ok"),
            ("Marcadores del caso", "Colecciones y notas separadas de los originales", "OPERATIVO", "ok"),
            ("Control de calidad", "Cobertura, archivos vacíos, hashes y discrepancias de firma", "OPERATIVO", "ok"),
            ("Cifrado del expediente", "AES-256-GCM por bloques; la contraseña nunca se almacena", "OPERATIVO", "ok"),
            ("Firma criptográfica", "Ed25519 y verificación independiente del expediente", "OPERATIVO", "ok"),
            ("Extracción física/JTAG", "Requiere hardware y autorización especializada", "NO DISPONIBLE POR ADB", "blocked"),
        ]
        let cards = modules.map { item in
            "<article class='\(item.3)'><h2>\(htmlEscape(item.0))</h2><p>\(htmlEscape(item.1))</p><b>\(htmlEscape(item.2))</b></article>"
        }.joined()
        let html = """
        <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{padding:28px;background:#091117;color:#e5f4f5;font:14px -apple-system}h1{font-size:28px}.search{width:100%;padding:11px;border-radius:10px;border:1px solid #34545f;background:#112028;color:white;margin:8px 0 20px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}article{padding:17px;border:1px solid #31515d;border-radius:14px;background:#13232b}article h2{font-size:16px}article p{color:#91a7ad;min-height:38px}article b{font-size:10px;color:#67efad}.wait b{color:#efc967}.blocked b{color:#ff777c}</style><script>function f(q){q=q.toLowerCase();document.querySelectorAll('article').forEach(x=>x.style.display=x.innerText.toLowerCase().includes(q)?'':'none')}</script></head><body><h1>Centro de herramientas</h1><p>Capacidades instaladas y dependencias técnicas.</p><input class="search" placeholder="Buscar herramienta…" oninput="f(this.value)"><section class="grid">\(cards)</section></body></html>
        """
        galleryWebView.loadHTMLString(html, baseURL: nil)
    }

    @objc private func showSystemDiagnostics() {
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        let resources = Bundle.main.resourceURL
        let python = pythonExecutableURL()
        let universalPython = resources?.appendingPathComponent("Python3.framework/Versions/Current/bin/python3")
        let adb = resources?.appendingPathComponent("platform-tools/adb")
        let verifier = resources?.appendingPathComponent("ForensicVerifier")
        let privacy = resources?.appendingPathComponent("PrivacyInfo.xcprivacy")
        let manager = FileManager.default
        let cases = casesRoot()
        let free = (try? cases.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage) ?? 0
        let mode = ((try? manager.attributesOfItem(atPath: cases.path)[.posixPermissions]) as? NSNumber)?.intValue ?? 0
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        let pythonVersion = commandOutput(python, ["--version"])
        let universalPythonVersion = universalPython.map { commandOutput($0, ["--version"]) } ?? "No encontrado"
        let adbVersion = adb.map { commandOutput($0, ["version"]).components(separatedBy: .newlines).first ?? "" } ?? "No encontrado"
        let signature = commandSucceeded(URL(fileURLWithPath: "/usr/bin/codesign"), ["--verify", "--deep", "--strict", Bundle.main.bundlePath])
        let checks: [(String, String, Bool)] = [
            ("Paquete de la aplicación", "Versión \(version) · compilación \(build) · \(ProcessInfo.processInfo.operatingSystemVersionString)", signature),
            ("Runtime Python", pythonVersion.isEmpty ? python.path : pythonVersion, manager.isExecutableFile(atPath: python.path)),
            ("Runtime universal Intel / Apple Silicon", "\(universalPythonVersion) · motor alterno y Pillow 11.3 verificados", universalPython.map { manager.isExecutableFile(atPath: $0.path) } ?? false),
            ("Android Debug Bridge", adbVersion, adb.map { manager.isExecutableFile(atPath: $0.path) } ?? false),
            ("Validador Ed25519 / FMLX", verifier?.path ?? "No encontrado", verifier.map { manager.isExecutableFile(atPath: $0.path) } ?? false),
            ("Manifiesto de privacidad", privacy?.lastPathComponent ?? "No encontrado", privacy.map { manager.fileExists(atPath: $0.path) } ?? false),
            ("Protección de expedientes", "\(cases.path) · permisos \(String(mode, radix: 8))", mode & 0o077 == 0),
            ("Espacio disponible", ByteCountFormatter.string(fromByteCount: free, countStyle: .file), free > 2_000_000_000),
        ]
        let cards = checks.map { name, detail, ok in
            "<article class='\(ok ? "ok" : "bad")'><span>\(ok ? "✓" : "!")</span><div><h2>\(htmlEscape(name))</h2><p>\(htmlEscape(detail))</p></div><b>\(ok ? "LISTO" : "REVISAR")</b></article>"
        }.joined()
        let ready = checks.filter(\.2).count
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#091117;color:#e7f4f5;font:14px -apple-system}header{padding:20px;border:1px solid #31515d;border-radius:16px;background:linear-gradient(120deg,#10252a,#0b2119)}h1{margin:0 0 6px;font-size:28px}header p{color:#a8bbc0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px;margin-top:16px}article{display:grid;grid-template-columns:38px 1fr auto;gap:12px;align-items:center;padding:15px;border:1px solid #31515d;border-radius:13px;background:#12222a}article>span{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;font-weight:900}.ok>span{background:#173f31;color:#62eca8}.bad>span{background:#4a272b;color:#ff8a91}h2{font-size:15px;margin:0 0 5px}p{margin:0;color:#98adb2;word-break:break-word}b{font-size:10px;color:#62eca8}.bad b{color:#ff8a91}</style></head><body><header><h1>Diagnóstico del sistema</h1><p>\(ready) de \(checks.count) comprobaciones listas. Ejecutado \(htmlEscape(Date().formatted())).</p></header><section class="grid">\(cards)</section></body></html>
        """
        galleryWebView.loadHTMLString(html, baseURL: nil)
        statusLabel.stringValue = ready == checks.count ? "● SYSTEM VERIFIED" : "● ATTENTION REQUIRED"
        statusLabel.textColor = ready == checks.count ? forensicGreen : .systemOrange
    }

    private func commandOutput(_ executable: URL, _ arguments: [String]) -> String {
        let process = Process(), pipe = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        } catch { return error.localizedDescription }
    }

    private func runCapturing(_ process: Process, stdout: Pipe, stderr: Pipe) throws -> (Data, Data) {
        let group = DispatchGroup()
        let lock = NSLock()
        var output = Data(), errors = Data()
        try process.run()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = stdout.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); output = data; lock.unlock(); group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = stderr.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); errors = data; lock.unlock(); group.leave()
        }
        process.waitUntilExit()
        group.wait()
        return (output, errors)
    }

    private func commandSucceeded(_ executable: URL, _ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus == 0 }
        catch { return false }
    }

    @objc private func showSecurityGuide() {
        showBundledDocument(named: "SEGURIDAD-Y-VERIFICACION", extension: "md", title: "Seguridad y verificación")
    }

    @objc private func showReleaseNotes() {
        showBundledDocument(named: "RELEASE-NOTES-3.2", extension: "md", title: "Novedades de Forensic Mobile Lab 3.2")
    }

    @objc private func showAuditReport() {
        showBundledDocument(named: "AUDIT-3.2", extension: "md", title: "Auditoría técnica de Forensic Mobile Lab 3.2")
    }

    private func showBundledDocument(named name: String, extension fileExtension: String, title: String) {
        guard let url = Bundle.main.url(forResource: name, withExtension: fileExtension),
              let content = try? String(contentsOf: url, encoding: .utf8) else {
            showError("No se encontró el documento incluido en esta compilación.")
            return
        }
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{max-width:1000px;margin:auto;padding:32px;background:#091117;color:#e6f3f4;font:14px -apple-system}h1{color:#5de6a1}pre{white-space:pre-wrap;word-break:break-word;line-height:1.55;background:#12222a;border:1px solid #31515d;border-radius:14px;padding:20px}</style></head><body><h1>\(htmlEscape(title))</h1><pre>\(htmlEscape(content))</pre></body></html>
        """
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        galleryWebView.loadHTMLString(html, baseURL: nil)
    }

    @objc private func showGalleryDashboard() {
        summaryBox.isHidden = currentCaseDirectory == nil
        artifactsBox.isHidden = false
        scrollDashboard(to: "gallery")
    }

    @objc private func showMultimediaDashboard() {
        summaryBox.isHidden = currentCaseDirectory == nil
        artifactsBox.isHidden = false
        scrollDashboard(to: "multimedia")
    }

    @objc private func showSQLDashboard() {
        scrollDashboard(to: "sql")
    }

    @objc private func showFileTreeDashboard() {
        scrollDashboard(to: "filesystem")
    }

    @objc private func showTimelineDashboard() {
        scrollDashboard(to: "timeline")
    }

    @objc private func showLinksDashboard() {
        scrollDashboard(to: "links")
    }

    @objc private func showReportDashboard() {
        scrollDashboard(to: "report")
    }

    @objc private func showAuditTrail() {
        guard let directory = currentCaseDirectory else {
            showError("Abre un expediente para consultar su cadena de custodia.")
            return
        }
        struct AuditRow {
            let timestamp: String, category: String, action: String, detail: String, hash: String
        }
        func payload(_ name: String) -> [String: Any] {
            let url = directory.appendingPathComponent("reports/\(name)")
            guard let data = try? Data(contentsOf: url),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
            return object
        }
        var rows: [AuditRow] = []
        let custody = payload("chain_of_custody.json")["events"] as? [[String: Any]] ?? []
        rows += custody.map {
            AuditRow(timestamp: $0["timestamp"] as? String ?? "—", category: "CUSTODIA",
                     action: $0["event"] as? String ?? "EVENTO",
                     detail: "Evento de adquisición", hash: $0["event_hash"] as? String ?? "—")
        }
        let annotations = payload("examiner_annotations.json")["annotations"] as? [[String: Any]] ?? []
        rows += annotations.map {
            AuditRow(timestamp: $0["timestamp_utc"] as? String ?? "—", category: "ANOTACIÓN",
                     action: $0["tag"] as? String ?? "NOTA",
                     detail: $0["note"] as? String ?? "", hash: $0["event_hash"] as? String ?? "—")
        }
        let application = payload("application_audit.json")["events"] as? [[String: Any]] ?? []
        rows += application.map {
            let details = (try? JSONSerialization.data(withJSONObject: $0["details"] ?? [:], options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) } ?? ""
            return AuditRow(timestamp: $0["timestamp_utc"] as? String ?? "—", category: "APLICACIÓN",
                            action: $0["action"] as? String ?? "EVENTO",
                            detail: details, hash: $0["event_hash"] as? String ?? "—")
        }
        rows.sort { $0.timestamp > $1.timestamp }
        let visible = rows.prefix(2000).map { row in
            "<article><time>\(htmlEscape(row.timestamp))</time><span>\(htmlEscape(row.category))</span><h2>\(htmlEscape(row.action))</h2><p>\(htmlEscape(row.detail))</p><code>SHA-256 · \(htmlEscape(row.hash))</code></article>"
        }.joined()
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#091117;color:#e7f4f5;font:14px -apple-system}header{padding:20px;border:1px solid #31515d;border-radius:16px;background:linear-gradient(120deg,#10252a,#0b2119)}h1{margin:0}header p{color:#9db2b7}article{display:grid;grid-template-columns:180px 100px 1fr;gap:8px 14px;padding:15px 4px;border-bottom:1px solid #29414a}time{color:#7dddb8;font:11px 'SF Mono',monospace}article>span{color:#57cee6;font-size:10px;font-weight:800}h2{font-size:14px;margin:0}p,code{grid-column:3;color:#a9bdc1;margin:0;word-break:break-word}code{font-size:9px;color:#6f979f}</style></head><body><header><h1>Cadena de custodia y actividad</h1><p>\(rows.count) eventos encadenados · mostrando \(min(rows.count, 2000)). La verificación de integridad valida sus enlaces y hashes.</p></header>\(visible.isEmpty ? "<p>No hay eventos disponibles.</p>" : visible)</body></html>
        """
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        galleryWebView.loadHTMLString(html, baseURL: nil)
    }

    @objc private func verifyIntegrity() {
        guard let caseDirectory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("Abre o genera un caso antes de verificar su integridad.")
            return
        }
        let report = caseDirectory.appendingPathComponent("reports/forensic_report.json")
        setRunning(true, status: "● VERIFYING HASHES")
        let process = Process()
        currentProcess = process
        process.executableURL = self.pythonExecutableURL()
        process.arguments = [script.path, "verify", report.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let processData = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let text = String(data: processData, encoding: .utf8) ?? ""
                var signatureText = "\nFirma Ed25519: expediente legado sin sello independiente."
                var signaturePresent = false
                var signatureOK = false
                let signatureFile = caseDirectory.appendingPathComponent("reports/case_signature.json")
                if FileManager.default.fileExists(atPath: signatureFile.path),
                   let verifier = Bundle.main.url(forResource: "ForensicVerifier", withExtension: nil) {
                    signaturePresent = true
                    let signedCheck = Process(), signedPipe = Pipe()
                    signedCheck.executableURL = verifier
                    signedCheck.arguments = ["verify", caseDirectory.path]
                    signedCheck.standardOutput = signedPipe; signedCheck.standardError = signedPipe
                    try? signedCheck.run()
                    let signatureData = signedPipe.fileHandleForReading.readDataToEndOfFile()
                    signedCheck.waitUntilExit()
                    signatureOK = signedCheck.terminationStatus == 0
                    signatureText = "\n" + (String(data: signatureData, encoding: .utf8) ?? "Sin resultado de firma")
                }
                let hashesValid = process.terminationStatus == 0
                let allValid = hashesValid && signaturePresent && signatureOK
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.currentProcess = nil
                    let legacyValid = hashesValid && !signaturePresent
                    self.setRunning(false, status: allValid ? "● INTEGRITY + SIGNATURE VERIFIED" : (legacyValid ? "● HASHES VERIFIED · UNSIGNED" : "● INTEGRITY FAILED"))
                    self.summaryBox.isHidden = false
                    self.artifactsBox.isHidden = false
                    self.summaryView.string = "INTEGRITY VERIFICATION\n\n\(text)\(signatureText)"
                    let alert = NSAlert()
                    alert.alertStyle = allValid ? .informational : (legacyValid ? .warning : .critical)
                    alert.messageText = allValid ? "Integridad y firma verificadas" : (legacyValid ? "Hashes válidos; expediente legado sin firma" : "La evidencia o la firma cambió")
                    alert.informativeText = allValid ? "Los hashes y la firma Ed25519 son válidos." : (legacyValid ? "El contenido coincide con su manifiesto SHA-256, pero este expediente antiguo todavía no tiene un sello Ed25519 independiente." : "Uno o más archivos o la firma no coinciden.")
                    alert.runModal()
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● VERIFY FAILED")
                    self?.showError(error.localizedDescription)
                }
            }
        }
    }

    @objc private func protectCurrentEvidence() {
        guard let directory = currentCaseDirectory else {
            showError("Abre o genera un expediente antes de proteger la evidencia.")
            return
        }
        setRunning(true, status: "● PROTECTING & RESEALING ORIGINALS")
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let count = try self.protectEvidenceFiles(in: directory)
                self.appendAuditEvent("EVIDENCE_PROTECTED_READ_ONLY", details: ["files": count], to: directory)
                let result = self.sealCaseSynchronously(directory)
                guard result.ok else {
                    throw NSError(domain: "ForensicMobileLab", code: 24, userInfo: [NSLocalizedDescriptionKey: "Los permisos se aplicaron, pero el sellado de comprobación falló.\n\n\(result.output)"])
                }
                DispatchQueue.main.async {
                    self.setRunning(false, status: "● ORIGINALS READ-ONLY · VERIFIED")
                    let alert = NSAlert()
                    alert.messageText = "Originales protegidos y verificados"
                    alert.informativeText = count == 1
                        ? "1 archivo de evidencia quedó en modo de solo lectura. El expediente fue resellado y verificado."
                        : "\(count) archivos de evidencia quedaron en modo de solo lectura. El expediente fue resellado y verificado."
                    alert.runModal()
                }
            } catch {
                DispatchQueue.main.async {
                    self.setRunning(false, status: "● PROTECTION FAILED")
                    self.showError("No fue posible completar la protección: \(error.localizedDescription)")
                }
            }
        }
    }

    private func protectEvidenceFiles(in directory: URL) throws -> Int {
        let report = directory.appendingPathComponent("reports/forensic_report.json")
        let data = try Data(contentsOf: report)
        guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let manifest = payload["manifest"] as? [[String: Any]] else {
            throw NSError(domain: "ForensicMobileLab", code: 21, userInfo: [NSLocalizedDescriptionKey: "El manifiesto del caso no es válido."])
        }
        let caseRoot = directory.resolvingSymlinksInPath().standardizedFileURL.path
        var protected = 0
        for item in manifest {
            guard let rawPath = item["evidence_path"] as? String else { continue }
            let file: URL
            if let relative = item["case_relative_path"] as? String,
               let rebased = safeCaseURL(relative, under: directory) {
                file = rebased.resolvingSymlinksInPath().standardizedFileURL
            } else if let rebased = legacyCaseURL(from: rawPath, under: directory) {
                file = rebased.resolvingSymlinksInPath().standardizedFileURL
            } else {
                file = URL(fileURLWithPath: rawPath).resolvingSymlinksInPath().standardizedFileURL
            }
            guard file.path == caseRoot || file.path.hasPrefix(caseRoot + "/") else {
                throw NSError(domain: "ForensicMobileLab", code: 22, userInfo: [NSLocalizedDescriptionKey: "El manifiesto contiene una ruta fuera del expediente: \(rawPath)"])
            }
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: file.path, isDirectory: &isDirectory), !isDirectory.boolValue else { continue }
            try FileManager.default.setAttributes([.posixPermissions: 0o440], ofItemAtPath: file.path)
            protected += 1
        }
        return protected
    }

    @objc private func backupCurrentCase() {
        guard let source = currentCaseDirectory else {
            showError("Abre o genera un expediente antes de crear el respaldo.")
            return
        }
        let panel = NSOpenPanel()
        panel.title = "Selecciona una carpeta de respaldo"
        panel.message = "Puedes elegir una carpeta de tu Synology cuando aparezca conectado en Ubicaciones."
        panel.prompt = "Respaldar aquí"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let backupRoot = panel.url else { return }
        let normalizedSource = source.resolvingSymlinksInPath().standardizedFileURL
        let normalizedRoot = backupRoot.resolvingSymlinksInPath().standardizedFileURL
        guard !normalizedRoot.path.hasPrefix(normalizedSource.path + "/") else {
            showError("La carpeta de respaldo no puede estar dentro del propio expediente.")
            return
        }
        let destination = normalizedRoot.appendingPathComponent(source.lastPathComponent, isDirectory: true)
        let partial = normalizedRoot.appendingPathComponent(".\(source.lastPathComponent).partial-\(timestamp())", isDirectory: true)
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            showError("Ya existe un respaldo con este nombre en la carpeta seleccionada.")
            return
        }
        setRunning(true, status: "● VERIFYING BEFORE BACKUP")
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let required = try self.directoryLogicalSize(normalizedSource) + 512 * 1024 * 1024
                let available = try self.availableCapacity(at: normalizedRoot)
                guard available >= required else {
                    throw NSError(domain: "ForensicMobileLab", code: 26, userInfo: [NSLocalizedDescriptionKey: "Espacio insuficiente para una copia verificada. Se requieren aproximadamente \(ByteCountFormatter.string(fromByteCount: required, countStyle: .file)); disponibles: \(ByteCountFormatter.string(fromByteCount: available, countStyle: .file))."])
                }
                self.appendAuditEvent("BACKUP_REQUESTED", details: ["destination": destination.path], to: normalizedSource)
                let originalCheck = self.sealCaseSynchronously(normalizedSource)
                guard originalCheck.ok else {
                    throw NSError(domain: "ForensicMobileLab", code: 27, userInfo: [NSLocalizedDescriptionKey: "El respaldo fue bloqueado porque la integridad del caso original falló.\n\n\(originalCheck.output)"])
                }
                try FileManager.default.copyItem(at: normalizedSource, to: partial)
                let copiedCheck = self.compareCaseCopy(source: normalizedSource, copy: partial)
                guard copiedCheck.ok else {
                    try? FileManager.default.trashItem(at: partial, resultingItemURL: nil)
                    throw NSError(domain: "ForensicMobileLab", code: 23, userInfo: [NSLocalizedDescriptionKey: "La copia no superó la verificación SHA-256.\n\n\(copiedCheck.output)"])
                }
                try FileManager.default.moveItem(at: partial, to: destination)
                DispatchQueue.main.async {
                    self.setRunning(false, status: "● BACKUP VERIFIED")
                    let alert = NSAlert()
                    alert.messageText = "Respaldo verificado"
                    alert.informativeText = "La copia se completó y superó la verificación SHA-256.\n\n\(destination.path)"
                    alert.addButton(withTitle: "Aceptar")
                    alert.addButton(withTitle: "Mostrar en Finder")
                    if alert.runModal() == .alertSecondButtonReturn {
                        NSWorkspace.shared.activateFileViewerSelecting([destination])
                    }
                }
            } catch {
                if FileManager.default.fileExists(atPath: partial.path) {
                    try? FileManager.default.trashItem(at: partial, resultingItemURL: nil)
                }
                DispatchQueue.main.async {
                    self.setRunning(false, status: "● BACKUP FAILED")
                    self.showError("No fue posible completar el respaldo: \(error.localizedDescription)")
                }
            }
        }
    }

    private func verifyCase(at directory: URL) -> (ok: Bool, output: String) {
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            return (false, "No se encontró el motor forense.")
        }
        let report = directory.appendingPathComponent("reports/forensic_report.json")
        let process = Process()
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "verify", report.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let processData = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let output = String(data: processData, encoding: .utf8) ?? ""
            guard process.terminationStatus == 0 else { return (false, output) }
            guard let verifier = Bundle.main.url(forResource: "ForensicVerifier", withExtension: nil) else {
                return (false, output + "\nNo se encontró el verificador Ed25519.")
            }
            let signature = Process(), signaturePipe = Pipe()
            signature.executableURL = verifier
            signature.arguments = ["verify", directory.path]
            signature.standardOutput = signaturePipe
            signature.standardError = signaturePipe
            try signature.run()
            let signatureData = signaturePipe.fileHandleForReading.readDataToEndOfFile()
            signature.waitUntilExit()
            let signatureOutput = String(data: signatureData, encoding: .utf8) ?? ""
            return (signature.terminationStatus == 0, output + "\n" + signatureOutput)
        } catch {
            return (false, error.localizedDescription)
        }
    }

    private func sealCaseSynchronously(_ directory: URL) -> (ok: Bool, output: String) {
        // Evita que dos acciones (p. ej. una anotación y una exportación)
        // reconstruyan simultáneamente el manifiesto y la firma del mismo caso.
        sealLock.lock()
        defer { sealLock.unlock() }
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py"),
              let verifier = Bundle.main.url(forResource: "ForensicVerifier", withExtension: nil) else {
            return (false, "Faltan los motores de sellado del expediente.")
        }
        let pythonSeal = Process(), pythonPipe = Pipe()
        pythonSeal.executableURL = pythonExecutableURL()
        pythonSeal.arguments = [script.path, "seal", directory.path]
        pythonSeal.standardOutput = pythonPipe
        pythonSeal.standardError = pythonPipe
        do {
            try pythonSeal.run()
            let pythonData = pythonPipe.fileHandleForReading.readDataToEndOfFile()
            pythonSeal.waitUntilExit()
            let pythonOutput = String(data: pythonData, encoding: .utf8) ?? ""
            guard pythonSeal.terminationStatus == 0 else { return (false, pythonOutput) }
            let signedSeal = Process(), signedPipe = Pipe()
            signedSeal.executableURL = verifier
            signedSeal.arguments = ["seal", directory.path]
            signedSeal.standardOutput = signedPipe
            signedSeal.standardError = signedPipe
            try signedSeal.run()
            let signedData = signedPipe.fileHandleForReading.readDataToEndOfFile()
            signedSeal.waitUntilExit()
            let signedOutput = String(data: signedData, encoding: .utf8) ?? ""
            guard signedSeal.terminationStatus == 0 else { return (false, pythonOutput + "\n" + signedOutput) }
            let verification = verifyCase(at: directory)
            return (verification.ok, pythonOutput + "\n" + signedOutput + "\n" + verification.output)
        } catch {
            return (false, error.localizedDescription)
        }
    }

    private func compareCaseCopy(source: URL, copy: URL) -> (ok: Bool, output: String) {
        do {
            let sourceFiles = try regularFiles(relativeTo: source)
            let copiedFiles = try regularFiles(relativeTo: copy)
            guard Set(sourceFiles.keys) == Set(copiedFiles.keys) else {
                let missing = Set(sourceFiles.keys).subtracting(copiedFiles.keys).sorted()
                let extra = Set(copiedFiles.keys).subtracting(sourceFiles.keys).sorted()
                return (false, "Archivos faltantes: \(missing)\nArchivos adicionales: \(extra)")
            }
            for relativePath in sourceFiles.keys.sorted() {
                guard let original = sourceFiles[relativePath], let duplicate = copiedFiles[relativePath] else { continue }
                let originalHash = try sha256File(original)
                let copiedHash = try sha256File(duplicate)
                guard originalHash == copiedHash else {
                    return (false, "SHA-256 distinto en: \(relativePath)")
                }
            }
            return (true, "\(sourceFiles.count) archivos comparados mediante SHA-256.")
        } catch {
            return (false, error.localizedDescription)
        }
    }

    private func regularFiles(relativeTo root: URL) throws -> [String: URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: []
        ) else { return [:] }
        var result: [String: URL] = [:]
        let normalizedRoot = root.resolvingSymlinksInPath().standardizedFileURL
        for case let file as URL in enumerator {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true {
                throw NSError(domain: "ForensicMobileLab", code: 24, userInfo: [NSLocalizedDescriptionKey: "El expediente contiene un enlace simbólico no permitido: \(file.path)"])
            }
            guard values.isRegularFile == true else { continue }
            let normalizedFile = file.resolvingSymlinksInPath().standardizedFileURL
            guard normalizedFile.path.hasPrefix(normalizedRoot.path + "/") else {
                throw NSError(domain: "ForensicMobileLab", code: 25, userInfo: [NSLocalizedDescriptionKey: "Se detectó una ruta fuera del expediente."])
            }
            let relative = String(normalizedFile.path.dropFirst(normalizedRoot.path.count + 1))
            if relative.split(separator: "/").contains(".ui_cache") { continue }
            result[relative] = normalizedFile
        }
        return result
    }

    private func sha256File(_ file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var digest = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            digest.update(data: chunk)
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func directoryLogicalSize(_ root: URL) throws -> Int64 {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
            options: []
        ) else { return 0 }
        var total: Int64 = 0
        for case let file as URL in enumerator {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            if values.isSymbolicLink == true {
                throw NSError(domain: "ForensicMobileLab", code: 28, userInfo: [NSLocalizedDescriptionKey: "El expediente contiene un enlace simbólico no permitido: \(file.lastPathComponent)"])
            }
            if values.isRegularFile == true { total += Int64(values.fileSize ?? 0) }
        }
        return total
    }

    private func availableCapacity(at location: URL) throws -> Int64 {
        let values = try location.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values.volumeAvailableCapacityForImportantUsage ?? 0
    }

    private func scrollDashboard(to identifier: String) {
        let script = "document.getElementById('\(identifier)')?.scrollIntoView({behavior:'smooth',block:'start'});"
        galleryWebView.evaluateJavaScript(script)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        guard url.scheme == "forensic" else {
            // Los expedientes pueden contener texto no confiable. El visor jamás
            // navega a Internet ni conserva cookies; solo muestra recursos locales.
            let localSchemes = Set(["file", "about", "data", "blob"])
            decisionHandler(localSchemes.contains(url.scheme?.lowercased() ?? "") ? .allow : .cancel)
            return
        }
        decisionHandler(.cancel)
        switch url.host {
        case "adb": connectADB()
        case "folder": selectDevice()
        case "demo": runDemo()
        case "ios": importIOSBackup()
        case "iphone-backup": createAutomaticIPhoneBackup()
        case "case":
            if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
               let path = components.queryItems?.first(where: { $0.name == "path" })?.value {
                let directory = URL(fileURLWithPath: path, isDirectory: true).resolvingSymlinksInPath().standardizedFileURL
                let root = casesRoot().resolvingSymlinksInPath().standardizedFileURL
                guard directory.path.hasPrefix(root.path + "/"),
                      FileManager.default.fileExists(atPath: directory.appendingPathComponent("reports/forensic_report.json").path) else {
                    showError("El enlace no apunta a un expediente administrado válido.")
                    return
                }
                currentCaseDirectory = directory
                openFolderButton.isEnabled = true
                loadReport(caseDirectory: directory, processLog: "Expediente reabierto desde Gestión de casos")
            }
        case "annotate":
            if let components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                let hash = components.queryItems?.first(where: { $0.name == "hash" })?.value ?? ""
                let path = components.queryItems?.first(where: { $0.name == "path" })?.value ?? ""
                annotateEvidence(hash: hash, path: path)
            }
        case "open":
            if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
               let path = components.queryItems?.first(where: { $0.name == "path" })?.value,
               let directory = currentCaseDirectory,
               let file = safeExistingCaseFile(path, under: directory) {
                NSWorkspace.shared.open(file)
            } else {
                showError("Se bloqueó una ruta externa o inexistente.")
            }
        default: break
        }
    }

    private func annotateEvidence(hash: String, path: String) {
        guard let directory = currentCaseDirectory else { return }
        let note = NSTextField(frame: NSRect(x: 0, y: 34, width: 420, height: 24))
        note.placeholderString = "Nota del examinador"
        let tag = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 200, height: 26))
        tag.addItems(withTitles: ["Relevante", "Revisar", "Revisado", "Duplicado", "Sin relevancia"])
        let accessory = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 62))
        accessory.addSubview(note)
        accessory.addSubview(tag)
        let alert = NSAlert()
        alert.messageText = "Anotar evidencia"
        alert.informativeText = path
        alert.accessoryView = accessory
        alert.addButton(withTitle: "Guardar anotación")
        alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let file = directory.appendingPathComponent("reports/examiner_annotations.json")
        var payload: [String: Any] = ["version": 1, "annotations": []]
        if let data = try? Data(contentsOf: file),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            payload = existing
        }
        var annotations = payload["annotations"] as? [[String: Any]] ?? []
        let previousHash = annotations.last?["event_hash"] as? String ?? String(repeating: "0", count: 64)
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let canonical = "\(previousHash)|\(timestamp)|\(hash)|\(path)|\(tag.titleOfSelectedItem ?? "")|\(note.stringValue)"
        let eventHash = sha256String(canonical)
        annotations.append([
            "timestamp_utc": timestamp,
            "examiner": NSFullUserName(),
            "evidence_sha256": hash,
            "path": path,
            "tag": tag.titleOfSelectedItem ?? "Revisar",
            "note": note.stringValue,
            "previous_hash": previousHash,
            "event_hash": eventHash,
        ])
        payload["annotations"] = annotations
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: file, options: .atomic)
        }
        resealCase(directory)
    }

    private func resealCase(_ directory: URL) {
        DispatchQueue.global(qos: .utility).async {
            _ = self.sealCaseSynchronously(directory)
        }
    }

    private func sha256String(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func appendAuditEvent(_ action: String, details: [String: Any] = [:], to directory: URL) {
        auditLock.lock()
        defer { auditLock.unlock() }
        let file = directory.appendingPathComponent("reports/application_audit.json")
        var events: [[String: Any]] = []
        if let data = try? Data(contentsOf: file),
           let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            events = payload["events"] as? [[String: Any]] ?? []
        }
        let previous = events.last?["event_hash"] as? String ?? String(repeating: "0", count: 64)
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let detailsData = (try? JSONSerialization.data(withJSONObject: details, options: [.sortedKeys])) ?? Data("{}".utf8)
        let detailsCanonical = String(data: detailsData, encoding: .utf8) ?? "{}"
        let canonical = "\(timestamp)|\(NSFullUserName())|\(action)|\(detailsCanonical)"
        let eventHash = sha256String("\(previous)|\(canonical)")
        events.append([
            "timestamp_utc": timestamp,
            "operator": NSFullUserName(),
            "action": action,
            "details": details,
            "canonical": canonical,
            "previous_hash": previous,
            "event_hash": eventHash,
        ])
        let payload: [String: Any] = ["version": 1, "hash_algorithm": "SHA-256", "events": events]
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            NSLog("Forensic Mobile Lab audit log error: %@", error.localizedDescription)
        }
    }

    @objc private func exportCurrentCase() {
        guard let directory = currentCaseDirectory else {
            showError("Abre o genera un expediente antes de exportarlo.")
            return
        }
        let panel = NSSavePanel()
        panel.title = "Exportar expediente forense"
        panel.nameFieldStringValue = "\(directory.lastPathComponent)-forensic-export.zip"
        panel.allowedContentTypes = [.zip]
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        setRunning(true, status: "● SEALING & EXPORTING")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let partial = destination.deletingLastPathComponent().appendingPathComponent(".\(destination.lastPathComponent).partial-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: partial) }
            do {
                let required = try self.directoryLogicalSize(directory) + 256 * 1024 * 1024
                guard try self.availableCapacity(at: destination.deletingLastPathComponent()) >= required else {
                    throw NSError(domain: "ForensicMobileLab", code: 34, userInfo: [NSLocalizedDescriptionKey: "No hay espacio suficiente para crear y cerrar el ZIP de forma segura."])
                }
                self.appendAuditEvent("ZIP_EXPORT_REQUESTED", details: ["filename": destination.lastPathComponent], to: directory)
                let seal = self.sealCaseSynchronously(directory)
                guard seal.ok else { throw NSError(domain: "ForensicMobileLab", code: 35, userInfo: [NSLocalizedDescriptionKey: "El expediente no superó el sellado previo.\n\n\(seal.output)"]) }
                let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
                process.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", directory.path, partial.path]
                try process.run(); process.waitUntilExit()
                guard process.terminationStatus == 0 else { throw NSError(domain: "ForensicMobileLab", code: Int(process.terminationStatus)) }
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: partial.path)
                if FileManager.default.fileExists(atPath: destination.path) {
                    _ = try FileManager.default.replaceItemAt(destination, withItemAt: partial)
                } else {
                    try FileManager.default.moveItem(at: partial, to: destination)
                }
                DispatchQueue.main.async { self.setRunning(false, status: "● VERIFIED EXPORT READY"); NSWorkspace.shared.activateFileViewerSelecting([destination]) }
            } catch {
                DispatchQueue.main.async { self.setRunning(false, status: "● EXPORT FAILED"); self.showError("No se pudo exportar el expediente: \(error.localizedDescription)") }
            }
        }
    }

    @objc private func exportEncryptedCase() {
        guard let directory = currentCaseDirectory,
              let verifier = Bundle.main.url(forResource: "ForensicVerifier", withExtension: nil) else {
            showError("Abre un expediente antes de crear la exportación cifrada.")
            return
        }
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 34, width: 380, height: 24))
        let confirmation = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        password.placeholderString = "Contraseña (mínimo 12 caracteres)"
        confirmation.placeholderString = "Confirmar contraseña"
        let fields = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 62)); fields.addSubview(password); fields.addSubview(confirmation)
        let alert = NSAlert(); alert.messageText = "Exportación forense cifrada"
        alert.informativeText = "Creará una imagen maestra lógica sellada y cifrada por bloques con AES-256-GCM. La carpeta actual permanece como copia de trabajo."
        alert.accessoryView = fields; alert.addButton(withTitle: "Crear .fmlx"); alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard password.stringValue.count >= 12, password.stringValue == confirmation.stringValue else {
            showError("Las contraseñas deben coincidir y contener al menos 12 caracteres."); return
        }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "\(directory.lastPathComponent)-master.fmlx"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        setRunning(true, status: "● SEALING & ENCRYPTING")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let temp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("\(UUID().uuidString)-master.zip")
            defer { try? FileManager.default.removeItem(at: temp) }
            do {
                guard let self else { return }
                let required = try self.directoryLogicalSize(directory) + 256 * 1024 * 1024
                guard try self.availableCapacity(at: temp.deletingLastPathComponent()) >= required,
                      try self.availableCapacity(at: destination.deletingLastPathComponent()) >= required else {
                    throw NSError(domain: "ForensicMobileLab", code: 30, userInfo: [NSLocalizedDescriptionKey: "No hay espacio suficiente para crear la copia temporal y el maestro cifrado."])
                }
                self.appendAuditEvent("ENCRYPTED_MASTER_REQUESTED", details: ["filename": destination.lastPathComponent, "format": "FMLX0001"], to: directory)
                let seal = self.sealCaseSynchronously(directory)
                guard seal.ok else { throw NSError(domain: "ForensicMobileLab", code: 31, userInfo: [NSLocalizedDescriptionKey: "No se pudo sellar y verificar el expediente.\n\n\(seal.output)"]) }
                let archive = Process(); archive.executableURL = URL(fileURLWithPath: "/usr/bin/ditto"); archive.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", directory.path, temp.path]; try archive.run(); archive.waitUntilExit()
                guard archive.terminationStatus == 0 else { throw NSError(domain: "ForensicMobileLab", code: 32, userInfo: [NSLocalizedDescriptionKey: "No se pudo crear la imagen maestra."]) }
                let encrypt = Process(), input = Pipe(), output = Pipe(); encrypt.executableURL = verifier; encrypt.arguments = ["encrypt", temp.path, destination.path]; encrypt.standardInput = input; encrypt.standardOutput = output; encrypt.standardError = output
                try encrypt.run(); input.fileHandleForWriting.write(Data(password.stringValue.utf8)); input.fileHandleForWriting.closeFile(); let response = output.fileHandleForReading.readDataToEndOfFile(); encrypt.waitUntilExit()
                guard encrypt.terminationStatus == 0 else { throw NSError(domain: "ForensicMobileLab", code: 33, userInfo: [NSLocalizedDescriptionKey: String(data: response, encoding: .utf8) ?? "Falló el cifrado."]) }
                DispatchQueue.main.async { self.setRunning(false, status: "● ENCRYPTED MASTER READY"); NSWorkspace.shared.activateFileViewerSelecting([destination]) }
            } catch { DispatchQueue.main.async { self?.setRunning(false, status: "● ENCRYPTION FAILED"); self?.showError(error.localizedDescription) } }
        }
    }

    @objc private func cancelAcquisition() {
        guard let process = currentProcess, process.isRunning else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Cancelar operación"
        alert.informativeText = currentOperationCleansPartials
            ? "Se detendrá el motor y se eliminarán únicamente archivos temporales con extensión .partial. La evidencia finalizada y los checkpoints permanecerán intactos."
            : "Se detendrá la operación actual. No se eliminará ningún archivo del expediente."
        alert.addButton(withTitle: "Cancelar operación")
        alert.addButton(withTitle: "Continuar trabajando")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        process.terminate()
        statusLabel.stringValue = "● CANCELLING SAFELY"
        if currentOperationCleansPartials, let directory = currentCaseDirectory,
           let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil) {
            for case let url as URL in enumerator where url.pathExtension == "partial" {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    @objc private func printReport() {
        let operation = NSPrintOperation(view: galleryWebView)
        operation.showsPrintPanel = true
        operation.showsProgressPanel = true
        operation.runModal(for: window, delegate: nil, didRun: nil, contextInfo: nil)
    }

    @objc private func compareCases() {
        let panel = NSOpenPanel()
        panel.title = "Selecciona exactamente dos reportes forenses"
        panel.message = "Compara archivos añadidos, eliminados y modificados mediante ruta y SHA-256."
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = true
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, panel.urls.count == 2 else {
            if panel.urls.count != 0 { showError("Debes seleccionar exactamente dos reportes JSON.") }
            return
        }
        let urls = panel.urls
        setRunning(true, status: "● COMPARING CASE MANIFESTS")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        do {
            func manifest(_ url: URL) throws -> [String: String] {
                let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
                let entries = object?["manifest"] as? [[String: Any]] ?? []
                return Dictionary(uniqueKeysWithValues: entries.compactMap {
                    guard let path = $0["logical_path"] as? String, let hash = $0["sha256"] as? String else { return nil }
                    return (path, hash)
                })
            }
            let first = try manifest(urls[0])
            let second = try manifest(urls[1])
            let added = second.keys.filter { first[$0] == nil }.sorted()
            let removed = first.keys.filter { second[$0] == nil }.sorted()
            let changed = first.keys.filter { second[$0] != nil && second[$0] != first[$0] }.sorted()
            func rows(_ values: [String], kind: String) -> String {
                values.map { "<li><b>\(kind)</b> \(self?.htmlEscape($0) ?? "")</li>" }.joined()
            }
            let html = """
            <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{padding:28px;background:#091117;color:#e6f4f5;font:14px -apple-system}h1{font-size:28px}.counts{display:flex;gap:12px}.counts b{padding:12px;border-radius:10px;background:#142830}li{padding:10px;border-bottom:1px solid #29404a}li b{color:#59d9f5}</style></head><body><h1>Comparación forense</h1><div class="counts"><b>Añadidos: \(added.count)</b><b>Eliminados: \(removed.count)</b><b>Modificados: \(changed.count)</b></div><h2>Cambios</h2><ul>\(rows(added, kind: "AÑADIDO"))\(rows(removed, kind: "ELIMINADO"))\(rows(changed, kind: "HASH CAMBIÓ"))</ul></body></html>
            """
            DispatchQueue.main.async {
                self?.setRunning(false, status: "● CASE COMPARISON READY")
                self?.summaryBox.isHidden = true
                self?.artifactsBox.isHidden = false
                self?.galleryWebView.loadHTMLString(html, baseURL: nil)
            }
        } catch {
            DispatchQueue.main.async {
                self?.setRunning(false, status: "● COMPARISON FAILED")
                self?.showError("No fue posible comparar los reportes: \(error.localizedDescription)")
            }
        }
        }
    }

    @objc private func searchCaseIndex() {
        guard let directory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("Abre un expediente antes de realizar una búsqueda indexada.")
            return
        }
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        field.placeholderString = "Texto, número, nombre de archivo o término FTS5"
        let alert = NSAlert()
        alert.messageText = "Búsqueda forense FTS5"
        alert.informativeText = "Consulta archivos, mensajes, contactos y metadatos del expediente."
        alert.accessoryView = field
        alert.addButton(withTitle: "Buscar")
        alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn, !field.stringValue.isEmpty else { return }
        let query = field.stringValue
        let index = directory.appendingPathComponent("reports/forensic_index.sqlite")
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "search", index.path, query]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        setRunning(true, status: "● SEARCHING FTS5")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let processData = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let output = String(data: processData, encoding: .utf8) ?? "[]"
                guard process.terminationStatus == 0 else { throw NSError(domain: "ForensicMobileLab.Search", code: Int(process.terminationStatus)) }
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.currentProcess = nil
                    self.setRunning(false, status: "● SEARCH READY")
                    let html = """
                    <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{padding:28px;background:#091117;color:#dff1f3;font:14px -apple-system}h1{color:#59d9f5}pre{white-space:pre-wrap;word-break:break-word;background:#12222a;border:1px solid #31515d;border-radius:14px;padding:18px;font:12px 'SF Mono',monospace}</style></head><body><h1>Resultados FTS5</h1><p>Consulta: \(self.htmlEscape(query))</p><pre>\(self.htmlEscape(output))</pre></body></html>
                    """
                    self.summaryBox.isHidden = true; self.artifactsBox.isHidden = false
                    self.galleryWebView.loadHTMLString(html, baseURL: nil)
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● SEARCH FAILED")
                    self?.showError("La búsqueda no pudo completarse. Verifica que el caso tenga un índice FTS5.")
                }
            }
        }
    }

    @objc private func runAdvancedIntelligence() {
        guard let directory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_advanced", withExtension: "py") else {
            showError("Abre un expediente y verifica que el motor avanzado esté instalado.")
            return
        }
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "build", directory.path]
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
        setRunning(true, status: "● ADVANCED ANALYSIS")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let output = String(data: data, encoding: .utf8) ?? ""
                guard process.terminationStatus == 0 else { throw NSError(domain: "ForensicMobileLab.Advanced", code: Int(process.terminationStatus)) }
                DispatchQueue.main.async { self?.statusLabel.stringValue = "● SEALING ADVANCED RESULTS" }
                guard let self else { return }
                let seal = self.sealCaseSynchronously(directory)
                guard seal.ok else {
                    throw NSError(domain: "ForensicMobileLab.Advanced", code: 2, userInfo: [NSLocalizedDescriptionKey: "El análisis terminó, pero sus resultados no superaron el sellado.\n\n\(seal.output)"])
                }
                DispatchQueue.main.async {
                    self.currentProcess = nil
                    self.summaryBox.isHidden = true; self.artifactsBox.isHidden = false
                    let catalog = directory.appendingPathComponent("reports/advanced/file_catalog.html")
                    if FileManager.default.fileExists(atPath: catalog.path) {
                        self.galleryWebView.loadFileURL(catalog, allowingReadAccessTo: directory)
                    } else {
                        self.galleryWebView.loadHTMLString("<html><body><h1>Inteligencia avanzada completada</h1><pre>\(self.htmlEscape(output))</pre></body></html>", baseURL: nil)
                    }
                    self.setRunning(false, status: "● ADVANCED READY · VERIFIED")
                }
            } catch { DispatchQueue.main.async { self?.currentProcess = nil; self?.setRunning(false, status: "● ADVANCED FAILED"); self?.showError("El análisis avanzado no pudo completarse: \(error.localizedDescription)") } }
        }
    }

    @objc private func showWorkstationCenter() {
        guard let script = Bundle.main.url(forResource: "forensic_advanced", withExtension: "py") else {
            showError("No se encontró el motor avanzado de inventario.")
            return
        }
        let process = Process(); currentProcess = process; process.executableURL = pythonExecutableURL(); process.arguments = [script.path, "disk-list"]
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
        setRunning(true, status: "● INVENTORYING DISKS")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        do {
            try process.run(); let processData = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            let output = String(data: processData, encoding: .utf8) ?? "{}"
            guard process.terminationStatus == 0 else { throw NSError(domain: "FML.DiskInventory", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: output]) }
            DispatchQueue.main.async {
            guard let self else { return }
            let page = """
            <html><head><meta charset='utf-8'><style>:root{color-scheme:dark}body{padding:28px;background:#091117;color:#e3f2f3;font:14px -apple-system}.card{padding:18px;border:1px solid #31515d;border-radius:14px;background:#13252d;margin:12px 0}a{display:inline-block;margin:5px;padding:9px 13px;background:#42d99a;color:#062016;border-radius:8px;text-decoration:none;font-weight:bold}pre{white-space:pre-wrap}</style></head><body><h1>Centro de discos, computadoras e iPhone</h1><div class='card'><h2>Discos detectados</h2><pre>\(self.htmlEscape(output))</pre><p>La captura RAW/DD exige seleccionar explícitamente la fuente, desmontarla y confirmar su identificador. Nunca captura automáticamente el disco activo.</p></div><div class='card'><h2>iPhone conectado</h2><p>Desbloquea el iPhone, conéctalo por USB y pulsa “Confiar”. El backup se guardará dentro del expediente, se podrá reanudar y al terminar se catalogará automáticamente.</p><a href='forensic://iphone-backup'>CREAR BACKUP AUTOMÁTICO</a><a href='forensic://ios'>IMPORTAR BACKUP EXISTENTE</a></div><div class='card'><h2>Seguridad</h2><p>FileVault, BitLocker y backups iOS cifrados no se evaden. Para decodificar contenido protegido se requiere la contraseña legal.</p></div></body></html>
            """
            self.currentProcess = nil; self.setRunning(false, status: "● DISK INVENTORY READY")
            self.summaryBox.isHidden = true; self.artifactsBox.isHidden = false; self.galleryWebView.loadHTMLString(page, baseURL: nil)
            }
        } catch { DispatchQueue.main.async { self?.currentProcess = nil; self?.setRunning(false, status: "● DISK INVENTORY FAILED"); self?.showError("No se pudo consultar el inventario de discos: \(error.localizedDescription)") } }
        }
    }

    private func importIOSBackup() {
        guard let directory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_advanced", withExtension: "py") else { showError("Abre un expediente primero."); return }
        let panel = NSOpenPanel(); panel.title = "Selecciona el backup autorizado de iPhone"; panel.canChooseDirectories = true; panel.canChooseFiles = false
        guard panel.runModal() == .OK, let backup = panel.url else { return }
        let output: URL
        do {
            let reports = try secureWritableDirectory("reports/advanced", under: directory)
            output = reports.appendingPathComponent("ios_inventory.json")
        } catch { showError("La estructura del expediente no es segura: \(error.localizedDescription)"); return }
        let process = Process(); currentProcess = process
        process.executableURL = pythonExecutableURL(); process.arguments = [script.path,"ios-inventory",backup.path,output.path]
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
        setRunning(true, status: "● IOS BACKUP INVENTORY")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let processData = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let message = String(data: processData, encoding: .utf8) ?? ""
                guard process.terminationStatus == 0 else {
                    throw NSError(domain: "FML.iOS", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: message])
                }
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.currentProcess = nil
                    self.setRunning(false, status: "● IOS INVENTORY READY")
                    self.resealCase(directory)
                    self.showWorkstationCenter()
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● IOS INVENTORY FAILED")
                    self?.showError("No se pudo inventariar el backup de iPhone: \(error.localizedDescription)")
                }
            }
        }
    }

    private func createAutomaticIPhoneBackup() {
        guard let directory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_advanced", withExtension: "py") else { showError("Abre o crea un expediente primero."); return }
        let available = (try? directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage) ?? 0
        guard available >= 10_000_000_000 else {
            showError("Se necesitan al menos 10 GB libres antes de iniciar un backup de iPhone. Disponibles: \(ByteCountFormatter.string(fromByteCount: available, countStyle: .file)).")
            return
        }
        let alert = NSAlert(); alert.messageText = "Crear backup completo del iPhone"; alert.informativeText = "Mantén el iPhone desbloqueado, conectado por USB y acepta Confiar. El proceso puede tardar y necesita espacio libre comparable al contenido del teléfono."; alert.addButton(withTitle:"Comenzar"); alert.addButton(withTitle:"Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let process=Process(); currentProcess=process; process.executableURL=pythonExecutableURL(); process.arguments=[script.path,"iphone-backup",directory.path]
        let pipe=Pipe(); process.standardOutput=pipe; process.standardError=pipe
        setRunning(true,status:"● IPHONE BACKUP"); summaryBox.isHidden=false; summaryView.string="Preparando backup automático…\n"
        pipe.fileHandleForReading.readabilityHandler={ [weak self] h in let d=h.availableData; if d.isEmpty { h.readabilityHandler=nil; return }; if let s=String(data:d,encoding:.utf8){ DispatchQueue.main.async { self?.summaryView.textStorage?.append(NSAttributedString(string:s)); self?.summaryView.scrollToEndOfDocument(nil) } } }
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            do { try process.run(); process.waitUntilExit(); pipe.fileHandleForReading.readabilityHandler=nil; guard process.terminationStatus==0 else { throw NSError(domain:"FML.iPhoneBackup",code:Int(process.terminationStatus)) }; DispatchQueue.main.async { self?.currentProcess=nil; self?.setRunning(false,status:"● IPHONE BACKUP COMPLETE"); self?.loadReport(caseDirectory:directory,processLog:"Backup de iPhone completado y catalogado"); self?.resealCase(directory) } }
            catch { DispatchQueue.main.async { self?.currentProcess=nil; self?.setRunning(false,status:"● IPHONE BACKUP INTERRUPTED"); self?.showError("No se completó el backup. Comprueba cable, desbloqueo y confianza. El expediente conserva el checkpoint para reintentar.") } }
        }
    }

    @objc private func exportRedactedReport() {
        guard let directory = currentCaseDirectory,
              let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("Abre un expediente antes de crear una copia redactada.")
            return
        }
        let panel = NSSavePanel()
        panel.title = "Guardar copia redactada"
        panel.nameFieldStringValue = "forensic_report_redacted.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let output = panel.url else { return }
        let source = directory.appendingPathComponent("reports/forensic_report.json")
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "redact", source.path, output.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        setRunning(true, status: "● CREATING REDACTED COPY")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let response = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    throw NSError(domain: "ForensicMobileLab.Redaction", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: String(data: response, encoding: .utf8) ?? "Falló la redacción"])
                }
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● REDACTED COPY READY")
                    NSWorkspace.shared.activateFileViewerSelecting([output])
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● REDACTION FAILED")
                    self?.showError("No se pudo crear la copia redactada. El reporte original no fue modificado.\n\n\(error.localizedDescription)")
                }
            }
        }
    }

    @objc private func runDemo() {
        let base = casesRoot().appendingPathComponent("Demo-\(timestamp())", isDirectory: true)
        execute(arguments: ["demo", "--workspace", base.path], caseDirectory: base.appendingPathComponent("case"))
    }

    @objc private func selectDevice() {
        let panel = NSOpenPanel()
        panel.title = "Selecciona la carpeta raíz del dispositivo simulado"
        panel.message = "Debe contener la estructura data/data/.../databases"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let device = panel.url else { return }
        presentFolderAcquisitionSetup(device)
    }

    private func presentFolderAcquisitionSetup(_ device: URL) {
        let caseField = NSTextField(string: "CASE-\(timestamp())")
        let examinerField = NSTextField(string: NSFullUserName())
        let examinerIDField = NSTextField(string: "")
        let evidenceField = NSTextField(string: "EVIDENCE-01")
        let authorityField = NSTextField(string: "")
        let scopeField = NSTextField(string: "Análisis lógico de la carpeta aportada")
        caseField.placeholderString = "Número del caso"
        examinerField.placeholderString = "Nombre del examinador"
        examinerIDField.placeholderString = "Identificación del examinador"
        evidenceField.placeholderString = "Número de evidencia"
        authorityField.placeholderString = "Autoridad: consentimiento, orden o autorización"
        scopeField.placeholderString = "Alcance autorizado"
        let confirmation = NSButton(checkboxWithTitle: "Confirmo la autorización y el alcance documentado", target: nil, action: nil)
        let source = NSTextField(wrappingLabelWithString: "FUENTE SELECCIONADA\n\(device.path)")
        source.font = .systemFont(ofSize: 11, weight: .semibold)
        source.textColor = forensicCyan
        let fields = [caseField, examinerField, examinerIDField, evidenceField, authorityField, scopeField]
        let setupViews: [NSView] = [source as NSView] + fields.map { $0 as NSView } + [confirmation as NSView]
        let stack = NSStackView(views: setupViews)
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 470, height: 285)
        fields.forEach { $0.widthAnchor.constraint(equalToConstant: 460).isActive = true }
        let alert = NSAlert()
        alert.messageText = "Documentar adquisición de laboratorio"
        alert.informativeText = "La carpeta se analizará en modo de lectura y se copiará a un expediente privado."
        alert.accessoryView = stack
        alert.addButton(withTitle: "Iniciar adquisición")
        alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard confirmation.state == .on,
              !caseField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !examinerIDField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !authorityField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !scopeField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            showError("Completa el caso, la identificación, la autoridad y el alcance; después confirma la autorización.")
            return
        }
        let caseDirectory = casesRoot().appendingPathComponent("Case-\(timestamp())", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: caseDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let profile: [String: Any] = [
                "case_number": caseField.stringValue,
                "examiner": examinerField.stringValue,
                "examiner_id": examinerIDField.stringValue,
                "evidence_number": evidenceField.stringValue,
                "legal_authority": authorityField.stringValue,
                "authorized_scope": scopeField.stringValue,
                "authorization_confirmed": true,
                "source_type": "EXAMINER_SUPPLIED_FOLDER",
                "source_path": device.path,
                "configured_at": ISO8601DateFormatter().string(from: Date()),
            ]
            let data = try JSONSerialization.data(withJSONObject: profile, options: [.prettyPrinted, .sortedKeys])
            let profileURL = caseDirectory.appendingPathComponent("case_profile.json")
            try data.write(to: profileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profileURL.path)
        } catch {
            showError("No se pudo crear el perfil privado del expediente: \(error.localizedDescription)")
            return
        }
        execute(arguments: ["acquire", device.path, caseDirectory.path], caseDirectory: caseDirectory)
    }

    @objc private func startADBFileCarving() {
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("No se encontró el motor forense dentro de la aplicación.")
            return
        }
        let outputDirectory = casesRoot()
            .appendingPathComponent("Carving-\(timestamp())", isDirectory: true)
            .appendingPathComponent("recuperacion_cellebrite", isDirectory: true)
        try? FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        setRunning(true, status: "● FILE CARVING")
        summaryBox.isHidden = false
        artifactsBox.isHidden = false
        summaryView.string = "Iniciando búsqueda JPEG/PNG por firmas en archivos públicos accesibles mediante ADB…\n"
        setGalleryMessage("File carving en curso", detail: "Las imágenes verificadas aparecerán al finalizar.")

        let process = Process()
        currentProcess = process
        currentOperationCleansPartials = true
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "carve-adb", outputDirectory.path]
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        let stdoutLock = NSLock()
        var stdoutData = Data()
        stdout.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            stdoutLock.lock()
            stdoutData.append(data)
            stdoutLock.unlock()
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                self?.summaryView.textStorage?.append(NSAttributedString(string: text))
                self?.summaryView.scrollToEndOfDocument(nil)
                if let progressLine = text.split(separator: "\n").last(where: { $0.contains("CARVING PROGRESS") }),
                   let range = progressLine.range(of: #"\d+/\d+"#, options: .regularExpression) {
                    self?.statusLabel.stringValue = "● CARVING \(progressLine[range])"
                }
            }
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                process.waitUntilExit()
                stdout.fileHandleForReading.readabilityHandler = nil
                stdoutLock.lock()
                let data = stdoutData
                stdoutLock.unlock()
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.currentProcess = nil
                    self.setRunning(false, status: process.terminationStatus == 0 ? "● CARVING COMPLETED" : "● CARVING FAILED")
                    guard process.terminationStatus == 0,
                          let report = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                        self.showError("El file carving no produjo un reporte válido. Revisa la autorización ADB.")
                        return
                    }
                    self.currentCaseDirectory = outputDirectory
                    self.openFolderButton.isEnabled = true
                    self.showCarvingResults(report, outputDirectory: outputDirectory)
                    self.resealCase(outputDirectory)
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● CARVING FAILED")
                    self?.showError("No se pudo iniciar el file carving: \(error.localizedDescription)")
                }
            }
        }
    }

    @objc private func showForensicToolkit() {
        guard let engine = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("No se encontró el motor forense dentro de la aplicación.")
            return
        }
        let controller = ForensicToolkitController(
            python: pythonExecutableURL(), engine: engine,
            reportsRoot: casesRoot().appendingPathComponent("ToolkitReports", isDirectory: true)
        )
        toolkitController = controller
        controller.showWindow(nil)
        controller.window?.center()
        controller.window?.makeKeyAndOrderFront(nil)
    }

    private func showCarvingResults(_ report: [String: Any], outputDirectory: URL) {
        let images = report["images"] as? [[String: Any]] ?? []
        let cards = images.prefix(100).map { item -> String in
            let path = URL(fileURLWithPath: item["output_path"] as? String ?? "")
            let name = htmlEscape(path.lastPathComponent)
            let format = htmlEscape(item["format"] as? String ?? "UNKNOWN")
            let classification = htmlEscape(item["classification"] as? String ?? "UNKNOWN")
            let source = htmlEscape(item["source_path"] as? String ?? "—")
            return """
            <article class="card" data-format="\(format)" data-classification="\(classification)" data-search="\(name.lowercased()) \(source.lowercased())">
              <button class="preview" onclick="openViewer(this)" data-name="\(name)" data-source="\(source)" data-sha="\(htmlEscape(item["sha256"] as? String ?? "—"))" data-source-sha="\(htmlEscape(item["source_sha256"] as? String ?? "—"))" data-crc="\(htmlEscape(item["crc32"] as? String ?? "—"))" data-offset="\(item["offset"] ?? 0)" data-stability="\(htmlEscape(item["source_stability"] as? String ?? "—"))" data-deletion="\(htmlEscape(item["deletion_status"] as? String ?? "UNDETERMINED"))"><img src="\(name)" loading="lazy"></button>
              <div class="badges"><span>\(format)</span><span>\(classification == "EMBEDDED_IMAGE" ? "EMBEBIDA" : "ARCHIVO")</span></div>
              <b>[!REC] \(name)</b><small>Origen: \(source)</small><small>Offset: \(item["offset"] ?? 0) · \(item["size"] ?? 0) bytes</small>
            </article>
            """
        }.joined()
        let formats = report["format_counts"] as? [String: Any] ?? [:]
        let embedded = (report["classification_counts"] as? [String: Any])?["EMBEDDED_IMAGE"] ?? 0
        let html = """
        <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:24px;background:#091117;color:#e4f3f4;font:14px -apple-system}h1{color:#58e8a0;margin:0}.summary{color:#9fb4ba}.stats{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}.stat,.filter{border:1px solid #31505d;border-radius:999px;padding:7px 11px;background:#12242b;color:#cbe5e6}.tools{position:sticky;top:0;z-index:2;display:flex;gap:9px;padding:12px 0;background:#091117ee}.tools input,.tools select{padding:9px 11px;border:1px solid #31505d;border-radius:9px;background:#101d23;color:#e4f3f4}.tools input{flex:1}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px}.card{padding:10px;border:1px solid #9b444b;border-radius:12px;background:#172229}.preview{width:100%;padding:0;border:0;background:none;cursor:zoom-in}.preview img{width:100%;height:155px;object-fit:contain;background:#070b0e;border-radius:8px}.badges{display:flex;gap:5px;margin-top:8px}.badges span{font-size:9px;font-weight:800;padding:4px 6px;border-radius:6px;background:#193b3d;color:#62eeb1}b,small{display:block;margin-top:7px;word-break:break-all}small{color:#9fb4ba;font-size:10px}.hidden{display:none!important}dialog{width:min(900px,90vw);border:1px solid #3d6570;border-radius:16px;background:#0c171d;color:#e4f3f4;padding:16px}dialog img{display:block;max-width:100%;max-height:65vh;margin:auto}dialog button{float:right;background:#35c9df;border:0;border-radius:8px;padding:8px 12px}.meta{white-space:pre-wrap;color:#a9c0c5;font:11px monospace;margin-top:12px}</style></head><body><h1>Recuperación por firmas</h1><p class="summary">\(htmlEscape(report["limitations"] as? String ?? ""))</p><div class="stats"><span class="stat">\(report["scanned_files"] ?? 0) archivos examinados</span><span class="stat">\(images.count) imágenes</span><span class="stat">\(embedded) embebidas</span><span class="stat">JPG \(formats["JPG"] ?? 0)</span><span class="stat">PNG \(formats["PNG"] ?? 0)</span><span class="stat">GIF \(formats["GIF"] ?? 0)</span><span class="stat">WEBP \(formats["WEBP"] ?? 0)</span></div><div class="tools"><input id="q" placeholder="Buscar por archivo u origen…" oninput="filter()"><select id="fmt" onchange="filter()"><option value="">Todos los formatos</option><option>JPG</option><option>PNG</option><option>GIF</option><option>WEBP</option></select><select id="cls" onchange="filter()"><option value="">Todas las clases</option><option value="EMBEDDED_IMAGE">Embebidas</option><option value="COMPLETE_VISIBLE_FILE">Archivos completos</option></select></div><section class="grid">\(cards)</section><dialog id="viewer"><button onclick="document.querySelector('#viewer').close()">Cerrar</button><img id="large"><div id="meta" class="meta"></div></dialog><script>function filter(){const q=document.querySelector('#q').value.toLowerCase(),f=document.querySelector('#fmt').value,c=document.querySelector('#cls').value;document.querySelectorAll('.card').forEach(x=>x.classList.toggle('hidden',!(x.dataset.search.includes(q)&&(!f||x.dataset.format===f)&&(!c||x.dataset.classification===c))))}function openViewer(b){document.querySelector('#large').src=b.querySelector('img').src;document.querySelector('#meta').textContent=b.dataset.name+'\\nOrigen: '+b.dataset.source+'\\nOffset: '+b.dataset.offset+'\\nSHA-256 extraído: '+b.dataset.sha+'\\nSHA-256 contenedor: '+b.dataset.sourceSha+'\\nCRC32: '+b.dataset.crc+'\\nEstabilidad: '+b.dataset.stability+'\\nEstado de borrado: '+b.dataset.deletion;document.querySelector('#viewer').showModal()}</script></body></html>
        """
        let htmlFile = outputDirectory.appendingPathComponent("carving_gallery.html")
        try? html.write(to: htmlFile, atomically: true, encoding: .utf8)
        galleryWebView.loadFileURL(htmlFile, allowingReadAccessTo: outputDirectory)
        summaryView.string = "File carving completado.\nImágenes verificadas: \(images.count)\nSalida: \(outputDirectory.path)"
    }

    @objc private func autoScanWhatsApp() {
        // «Analizar WhatsApp» es el único punto de entrada: reutiliza una pareja ya
        // cargada o ejecuta en segundo plano la búsqueda automática Backup + Clave.
        if whatsAppBackupPath != nil, whatsAppKeyPath != nil {
            analyzeWhatsAppBackup()
            return
        }
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("No se encontró el motor forense dentro de la aplicación.")
            return
        }
        let importDirectory = casesRoot().appendingPathComponent("WhatsAppImports", isDirectory: true)
        do { _ = try secureWritableDirectory("WhatsAppImports", under: casesRoot()) }
        catch { showError("No se pudo preparar una carpeta privada y segura para WhatsApp: \(error.localizedDescription)"); return }
        let destination = importDirectory.appendingPathComponent("msgstore.db.crypt14")
        let keyDestination = importDirectory.appendingPathComponent("whatsapp.key")
        setRunning(true, status: "● BUSCANDO CRYPT14")
        summaryBox.isHidden = false
        artifactsBox.isHidden = false
        summaryView.string = "Buscando backups .db.crypt14 en rutas de WhatsApp accesibles mediante ADB…"
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "whatsapp-auto-scan", "--output", destination.path, "--key-output", keyDestination.path]
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                guard let self else { return }
                let (outputData, errorData) = try self.runCapturing(process, stdout: stdout, stderr: stderr)
                let errorText = String(data: errorData, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    self.currentProcess = nil
                    self.setRunning(false, status: process.terminationStatus == 0 ? "● WHATSAPP BACKUP READY" : "● CRYPT14 NOT FOUND")
                    guard process.terminationStatus == 0,
                          let result = try? JSONSerialization.jsonObject(with: outputData) as? [String: Any],
                          let localPath = result["local_path"] as? String else {
                        self.summaryView.string = errorText
                        self.showError("No se encontró un backup .db.crypt14 accesible. Comprueba ADB, autorización y permisos de almacenamiento.")
                        return
                    }
                    self.whatsAppBackupPath = URL(fileURLWithPath: localPath)
                    let keyResult = result["key"] as? [String: Any]
                    if let keyLocalPath = keyResult?["local_path"] as? String {
                        self.whatsAppKeyPath = URL(fileURLWithPath: keyLocalPath)
                    }
                    self.summaryView.string = """
                    ✅ AUTOESCANEO DE WHATSAPP COMPLETADO

                    Remoto : \(result["remote_path"] ?? "—")
                    Local  : \(localPath)
                    Tamaño : \(result["size"] ?? 0) bytes
                    SHA-256: \(result["sha256"] ?? "—")
                    CRC32  : \(result["crc32"] ?? "—")
                    Clave  : \(keyResult?["local_path"] ?? "No encontrada en almacenamiento público")

                    Ruta interna actualizada para análisis:
                    \(localPath)
                    """
                    let alert = NSAlert()
                    if self.whatsAppKeyPath != nil {
                        alert.messageText = "✅ Extracción completa: Archivo y Clave detectados. Analizando..."
                        alert.informativeText = "Se usará el archivo key completo con wa-crypt-tools."
                    } else {
                        alert.alertStyle = .warning
                        alert.messageText = "⚠️ Backup encontrado, pero falta la clave en esta carpeta"
                        alert.informativeText = "Puedes seleccionar manualmente la clave correspondiente."
                    }
                    alert.addButton(withTitle: "Aceptar")
                    alert.runModal()
                    if self.whatsAppKeyPath != nil {
                        self.analyzeWhatsAppBackup()
                    } else {
                        self.selectWhatsAppKey()
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● AUTO-SCAN FAILED")
                    self?.showError("No se pudo iniciar el autoescaneo: \(error.localizedDescription)")
                }
            }
        }
    }

    @objc private func selectWhatsAppKey() {
        let panel = NSOpenPanel()
        panel.title = "Selecciona la clave correspondiente al backup Crypt14"
        panel.message = "Para Crypt14 normalmente es el archivo llamado key. La app no extrae ni intenta adivinar claves."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let key = panel.url else {
            whatsAppKeyPath = nil
            return
        }
        whatsAppKeyPath = key
        statusLabel.stringValue = "● CRYPT14 KEY SELECTED"
    }

    @objc private func analyzeWhatsAppBackup() {
        guard let encrypted = whatsAppBackupPath,
              let key = whatsAppKeyPath,
              let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("Primero autoescanea el backup y selecciona su clave Crypt14 correspondiente.")
            return
        }
        let decrypted = encrypted.deletingLastPathComponent().appendingPathComponent("msgstore.db")
        setRunning(true, status: "● DECRYPTING CRYPT14")
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "whatsapp-decrypt", encrypted.path, key.path, decrypted.path]
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                guard let self else { return }
                let (outputData, errorData) = try self.runCapturing(process, stdout: stdout, stderr: stderr)
                let errorText = String(data: errorData, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    self.currentProcess = nil
                    self.setRunning(false, status: process.terminationStatus == 0 ? "● WHATSAPP ANALYZED" : "● DECRYPTION FAILED")
                    guard process.terminationStatus == 0,
                          let result = try? JSONSerialization.jsonObject(with: outputData) as? [String: Any],
                          let databasePath = result["decrypted_path"] as? String,
                          let analysisPath = result["analysis_path"] as? String else {
                        self.summaryView.string = errorText
                        self.showError("No fue posible descifrar Crypt14. Verifica que la clave pertenezca exactamente a este backup.")
                        return
                    }
                    self.whatsAppDecryptedPath = URL(fileURLWithPath: databasePath)
                    self.showWhatsAppAnalysis(URL(fileURLWithPath: analysisPath), result: result)
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● DECRYPTION FAILED")
                    self?.showError("No se pudo ejecutar el análisis: \(error.localizedDescription)")
                }
            }
        }
    }

    private func showWhatsAppAnalysis(_ analysisURL: URL, result: [String: Any]) {
        guard let data = try? Data(contentsOf: analysisURL),
              let analysis = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            showError("La base fue descifrada, pero el reporte de análisis no pudo abrirse.")
            return
        }
        let artifacts = analysis["artifacts"] as? [[String: Any]] ?? []
        let cards = artifacts.prefix(1000).map { artifact -> String in
            let type = htmlEscape((artifact["artifact_type"] as? String ?? "registro").uppercased())
            let table = htmlEscape(artifact["source_table"] as? String ?? "—")
            let record = jsonHTML(artifact["record"] ?? [:])
            return "<article><b>\(type) · \(table)</b><pre>\(record)</pre></article>"
        }.joined()
        let html = """
        <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{padding:28px;background:#091117;color:#e4f3f4;font:14px -apple-system}h1{color:#5de6a1}header{padding:18px;border:1px solid #2d6155;border-radius:14px;background:#10251f}article{margin:12px 0;padding:14px;border:1px solid #31515d;border-radius:12px;background:#12222a}pre{white-space:pre-wrap;word-break:break-word;color:#cce0e3;font:11px 'SF Mono',monospace}</style></head><body><header><h1>WhatsApp Crypt14 analizado</h1><p>SQLite integrity: \(htmlEscape(String(describing: result["sqlite_integrity"] ?? "—"))) · Registros: \(artifacts.count)</p><p>SHA-256 descifrado: \(htmlEscape(result["decrypted_sha256"] as? String ?? "—"))</p></header>\(cards.isEmpty ? "<p>No se detectaron tablas compatibles.</p>" : cards)</body></html>
        """
        summaryBox.isHidden = true
        artifactsBox.isHidden = false
        galleryWebView.loadHTMLString(html, baseURL: analysisURL.deletingLastPathComponent())
    }

    @objc private func connectADB() {
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("No se encontró el motor forense dentro de la aplicación.")
            return
        }
        setRunning(true, status: "● DETECTING ANDROID")
        summaryBox.isHidden = false
        artifactsBox.isHidden = false
        summaryView.string = "[\(clock())] Buscando dispositivos ADB…\n[\(clock())] Verificando autorización RSA y telemetría de solo lectura…"
        let process = Process()
        currentProcess = process
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path, "probe"]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                guard let self else { return }
                let (outputData, errorData) = try self.runCapturing(process, stdout: stdout, stderr: stderr)
                DispatchQueue.main.async {
                    self.currentProcess = nil
                    self.setRunning(false, status: process.terminationStatus == 0 ? "● DEVICE DETECTED" : "● DEVICE NOT READY")
                    guard process.terminationStatus == 0,
                          let info = try? JSONSerialization.jsonObject(with: outputData) as? [String: Any] else {
                        let detail = String(data: errorData, encoding: .utf8) ?? "ADB no devolvió diagnóstico."
                        self.summaryView.string = detail
                        self.showError("No se detectó un Android autorizado. Desbloquea el teléfono, activa Depuración USB y acepta la huella RSA.\n\n\(detail)")
                        return
                    }
                    self.presentAcquisitionSetup(info)
                }
            } catch {
                DispatchQueue.main.async {
                    self?.currentProcess = nil
                    self?.setRunning(false, status: "● DEVICE NOT READY")
                    self?.showError("No fue posible ejecutar la detección ADB: \(error.localizedDescription)")
                }
            }
        }
    }

    private func presentAcquisitionSetup(_ info: [String: Any]) {
        let identity = info["identity"] as? [String: Any] ?? [:]
        let locked = info["locked"] as? Bool ?? false
        let deviceText = "\(identity["manufacturer"] ?? "Android") \(identity["model"] ?? "")"
        let localCapacity = (try? casesRoot().resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage) ?? 0
        let localFree = ByteCountFormatter.string(fromByteCount: localCapacity, countStyle: .file)
        summaryView.string = """
        DEVICE PREFLIGHT — VERIFIED

        Modelo           : \(deviceText)
        Serie            : \(identity["serial"] ?? "—")
        Sistema          : \(identity["platform"] ?? "Android")
        Parche seguridad : \(info["security_patch"] ?? "—")
        Batería          : \(info["battery_level"] ?? "—")%
        Almacenamiento   : \(info["storage_used"] ?? "—") usado
        Disponible Android: \(info["storage_available_kb"] ?? "—") KB
        Espacio libre Mac : \(localFree)
        Configuración USB : \(info["usb_configuration"] ?? "—")
        ADB autorizado   : SÍ
        Pantalla bloqueada: \(locked ? "SÍ — desbloquea antes de continuar" : "NO")
        """

        let caseField = NSTextField(string: "CASE-\(timestamp())")
        caseField.placeholderString = "Número del caso"
        let examinerField = NSTextField(string: NSFullUserName())
        examinerField.placeholderString = "Examinador"
        let evidenceField = NSTextField(string: "EVIDENCE-01")
        evidenceField.placeholderString = "Número de evidencia"
        let examinerIDField = NSTextField(string: "")
        examinerIDField.placeholderString = "Identificación del examinador"
        let organizationField = NSTextField(string: "")
        organizationField.placeholderString = "Organización / laboratorio"
        let authorityField = NSTextField(string: "")
        authorityField.placeholderString = "Autoridad: consentimiento, orden o autorización"
        let scopeField = NSTextField(string: "")
        scopeField.placeholderString = "Alcance autorizado de la adquisición"
        let authorizationCheck = NSButton(checkboxWithTitle: "Confirmo que tengo autorización y que el alcance escrito es correcto", target: nil, action: nil)
        let profilePopup = NSPopUpButton(frame: .zero, pullsDown: false)
        profilePopup.addItems(withTitles: ["Completo", "Rápido", "Solo comunicaciones", "Galería completa", "Recuperación lógica", "Personalizado"])
        profilePopup.selectItem(withTitle: "Completo")
        let photos = NSButton(checkboxWithTitle: "Fotos, videos y metadatos", target: nil, action: nil)
        let messages = NSButton(checkboxWithTitle: "SMS, WhatsApp, llamadas y contactos", target: nil, action: nil)
        let documents = NSButton(checkboxWithTitle: "Documentos y descargas", target: nil, action: nil)
        let recovery = NSButton(checkboxWithTitle: "Cachés y recuperación lógica [!REC]", target: nil, action: nil)
        let tree = NSButton(checkboxWithTitle: "Árbol del sistema de archivos", target: nil, action: nil)
        [photos, messages, documents, recovery, tree].forEach { $0.state = .on }
        let deviceLabel = NSTextField(wrappingLabelWithString: "DISPOSITIVO: \(deviceText)\nSERIE: \(identity["serial"] ?? "—")  •  ANDROID: \(identity["os_version"] ?? "—")")
        deviceLabel.font = .systemFont(ofSize: 11, weight: .semibold)
        deviceLabel.textColor = forensicCyan
        let contentLabel = NSTextField(labelWithString: "CONTENIDO AUTORIZADO")
        contentLabel.font = .systemFont(ofSize: 11, weight: .bold)
        let profileLabel = NSTextField(labelWithString: "PERFIL DE ADQUISICIÓN")
        profileLabel.font = .systemFont(ofSize: 11, weight: .bold)
        let stack = NSStackView(views: [deviceLabel, caseField, examinerField, examinerIDField, organizationField, evidenceField, authorityField, scopeField, authorizationCheck, profileLabel, profilePopup, contentLabel, photos, messages, documents, recovery, tree])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 460, height: 470)
        caseField.widthAnchor.constraint(equalToConstant: 450).isActive = true
        examinerField.widthAnchor.constraint(equalToConstant: 450).isActive = true
        evidenceField.widthAnchor.constraint(equalToConstant: 450).isActive = true
        [examinerIDField, organizationField, authorityField, scopeField].forEach { $0.widthAnchor.constraint(equalToConstant: 450).isActive = true }

        let alert = NSAlert()
        alert.messageText = locked ? "Dispositivo detectado, pero bloqueado" : "Configurar adquisición lógica"
        alert.informativeText = locked ? "Desbloquea manualmente el teléfono antes de iniciar." : "Revisa el caso y selecciona las categorías autorizadas."
        alert.accessoryView = stack
        alert.addButton(withTitle: locked ? "Revisar nuevamente" : "Iniciar adquisición")
        alert.addButton(withTitle: "Cancelar")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        if locked {
            connectADB()
            return
        }
        guard authorizationCheck.state == .on,
              !examinerIDField.stringValue.trimmingCharacters(in: .whitespaces).isEmpty,
              !authorityField.stringValue.trimmingCharacters(in: .whitespaces).isEmpty,
              !scopeField.stringValue.trimmingCharacters(in: .whitespaces).isEmpty else {
            showError("Debes identificar al examinador y documentar la autoridad y el alcance autorizado.")
            return
        }
        let manualSelection = [
            photos.state == .on ? "photos_media" : nil,
            messages.state == .on ? "communications" : nil,
            documents.state == .on ? "documents" : nil,
            recovery.state == .on ? "logical_recovery" : nil,
            tree.state == .on ? "file_tree" : nil,
        ].compactMap { $0 }
        let selected: [String]
        switch profilePopup.titleOfSelectedItem {
        case "Rápido": selected = ["photos_media", "communications"]
        case "Solo comunicaciones": selected = ["communications"]
        case "Galería completa": selected = ["photos_media", "documents"]
        case "Recuperación lógica": selected = ["photos_media", "logical_recovery"]
        case "Personalizado": selected = manualSelection
        default: selected = ["photos_media", "communications", "documents", "logical_recovery", "file_tree"]
        }
        guard !selected.isEmpty else {
            showError("Selecciona al menos una categoría de contenido.")
            return
        }
        let caseDirectory = casesRoot().appendingPathComponent("ADB-\(timestamp())", isDirectory: true)
        let profile: [String: Any] = [
            "case_number": caseField.stringValue,
            "examiner": examinerField.stringValue,
            "examiner_id": examinerIDField.stringValue,
            "organization": organizationField.stringValue,
            "evidence_number": evidenceField.stringValue,
            "legal_authority": authorityField.stringValue,
            "authorized_scope": scopeField.stringValue,
            "authorization_confirmed": true,
            "mac_time_utc": ISO8601DateFormatter().string(from: Date()),
            "mac_timezone": TimeZone.current.identifier,
            "device_time": info["device_time"] ?? "no disponible",
            "device_timezone": info["device_timezone"] ?? "no disponible",
            "selected_content": selected,
            "acquisition_profile": profilePopup.titleOfSelectedItem ?? "Personalizado",
            "device_preflight": info,
            "configured_at": ISO8601DateFormatter().string(from: Date()),
        ]
        do {
            try FileManager.default.createDirectory(at: caseDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try JSONSerialization.data(withJSONObject: profile, options: [.prettyPrinted, .sortedKeys])
            let profileURL = caseDirectory.appendingPathComponent("case_profile.json")
            try data.write(to: profileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profileURL.path)
        } catch {
            showError("No se pudo guardar el perfil legal privado del expediente: \(error.localizedDescription)")
            return
        }
        execute(arguments: ["adb", caseDirectory.path, "--categories"] + selected, caseDirectory: caseDirectory)
    }

    @objc private func selectReport() {
        let panel = NSOpenPanel()
        panel.title = "Abrir reporte forense"
        panel.message = "Selecciona forensic_report.json"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let report = panel.url else { return }
        let caseDirectory = report.deletingLastPathComponent().deletingLastPathComponent()
        currentCaseDirectory = caseDirectory
        openFolderButton.isEnabled = true
        loadReport(caseDirectory: caseDirectory, processLog: "Reporte existente: \(report.path)")
        statusLabel.stringValue = "● REPORT LOADED"
    }

    @objc private func openCaseFolder() {
        guard let directory = currentCaseDirectory else { return }
        NSWorkspace.shared.open(directory)
    }

    private func execute(arguments: [String], caseDirectory: URL) {
        guard let script = Bundle.main.url(forResource: "forensic_mobile_lab", withExtension: "py") else {
            showError("No se encontró el motor forense dentro de la aplicación.")
            return
        }
        setRunning(true, status: "● ACQUISITION ACTIVE")
        currentCaseDirectory = caseDirectory
        summaryBox.isHidden = false
        artifactsBox.isHidden = false
        summaryView.string = "[\(clock())] INITIALIZING SESSION\n[\(clock())] Connecting transport…\n[\(clock())] Validating authorized handshake…"
        setGalleryMessage("Adquisición en curso", detail: "Esperando fotografías y verificación SHA-256/CRC32…")

        let process = Process()
        currentProcess = process
        currentOperationCleansPartials = true
        process.executableURL = pythonExecutableURL()
        process.arguments = [script.path] + arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let logLock = NSLock()
        var logData = Data()
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            logLock.lock()
            logData.append(chunk)
            logLock.unlock()
            guard let text = String(data: chunk, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                guard let self else { return }
                self.summaryView.textStorage?.append(NSAttributedString(
                    string: text,
                    attributes: [
                        .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
                        .foregroundColor: NSColor(calibratedRed: 0.07, green: 0.20, blue: 0.14, alpha: 1),
                    ]
                ))
                self.summaryView.scrollToEndOfDocument(nil)
                if text.contains("ACQUIRING") { self.statusLabel.stringValue = "● ACQUIRING FILES" }
                if text.contains("VERIFIED") { self.statusLabel.stringValue = "● HASH VERIFIED" }
            }
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try process.run()
                let caffeinate = Process()
                caffeinate.executableURL = URL(fileURLWithPath: "/usr/bin/caffeinate")
                caffeinate.arguments = ["-i", "-w", "\(process.processIdentifier)"]
                try? caffeinate.run()
                process.waitUntilExit()
                output.fileHandleForReading.readabilityHandler = nil
                logLock.lock()
                let completedData = logData
                logLock.unlock()
                let log = String(data: completedData, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.currentProcess = nil
                    if process.terminationStatus == 0 {
                        if let verifier = Bundle.main.url(forResource: "ForensicVerifier", withExtension: nil) {
                            let seal = Process(); seal.executableURL = verifier; seal.arguments = ["seal", caseDirectory.path]; try? seal.run(); seal.waitUntilExit()
                        }
                        self.currentCaseDirectory = caseDirectory
                        self.openFolderButton.isEnabled = true
                        self.loadReport(caseDirectory: caseDirectory, processLog: log)
                    } else {
                        self.summaryView.string = log
                        self.setGalleryMessage("Adquisición sin resultados", detail: "No se produjeron artefactos visibles.")
                        self.showError("La adquisición terminó con código \(process.terminationStatus).\n\n\(log)")
                    }
                        self.setRunning(false, status: process.terminationStatus == 0 ? "● COMPLETED" : "● FAILED")
                }
            } catch {
                DispatchQueue.main.async {
                    self?.setRunning(false, status: "● FAILED")
                    self?.showError("No fue posible iniciar el motor: \(error.localizedDescription)")
                }
            }
        }
    }

    private func loadReport(caseDirectory: URL, processLog: String) {
        summaryBox.isHidden = false
        artifactsBox.isHidden = false
        let reportURL = caseDirectory.appendingPathComponent("reports/forensic_report.json")
        do {
            let data = try Data(contentsOf: reportURL)
            guard let report = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NSError(domain: "ForensicMobileLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Formato de reporte inválido"])
            }
            let caseInfo = report["case"] as? [String: Any] ?? [:]
            let device = report["device"] as? [String: Any] ?? [:]
            var manifest = report["manifest"] as? [[String: Any]] ?? []
            for index in manifest.indices {
                if let relative = manifest[index]["case_relative_path"] as? String,
                   let rebased = safeCaseURL(relative, under: caseDirectory) {
                    manifest[index]["evidence_path"] = rebased.path
                } else if let rawPath = manifest[index]["evidence_path"] as? String,
                          let rebased = legacyCaseURL(from: rawPath, under: caseDirectory) {
                    manifest[index]["evidence_path"] = rebased.path
                }
                if let relative = manifest[index]["thumbnail_relative_path"] as? String,
                   let rebased = safeCaseURL(relative, under: caseDirectory) {
                    manifest[index]["thumbnail_path"] = rebased.path
                } else if let rawPath = manifest[index]["thumbnail_path"] as? String,
                          let rebased = legacyCaseURL(from: rawPath, under: caseDirectory) {
                    manifest[index]["thumbnail_path"] = rebased.path
                }
            }
            let artifacts = report["artifacts"] as? [[String: Any]] ?? []
            let databaseAnalysis = report["database_analysis"] as? [String: Any] ?? [:]
            let fileTree = report["file_system_tree"] as? [String: Any] ?? [:]
            let timeline = report["timeline"] as? [[String: Any]] ?? []
            let smartLinks = report["smart_links"] as? [[String: Any]] ?? []
            let evidenceQuality = report["evidence_quality"] as? [String: Any] ?? [:]
            let parserRegistry = report["parser_registry"] as? [[String: Any]] ?? []
            let statistics = report["statistics"] as? [String: Any] ?? [:]
            let warnings = report["warnings"] as? [String] ?? []
            let counts = Dictionary(grouping: artifacts, by: { ($0["artifact_type"] as? String) ?? "unknown" }).mapValues(\.count)
            let recoveredCount = manifest.filter { ($0["is_recovered"] as? Bool) == true }.count

            summaryView.string = """
            ╔══════════════════════════════════════════════╗
            ║              ACQUISITION COMPLETE            ║
            ╚══════════════════════════════════════════════╝

            SESSION ID : \(caseInfo["acquisition_id"] ?? "—")
            DEVICE     : \(device["manufacturer"] ?? "—") \(device["model"] ?? "—")
            SERIAL     : \(device["serial"] ?? "—")
            PLATFORM   : \(device["platform"] ?? "—") \(device["os_version"] ?? "")
            TRANSPORT  : \(device["transport"] ?? "—")
            STATUS     : AUTHORIZED

            FILES      : \(manifest.count)
            ARTIFACTS  : \(artifacts.count)
            SMS        : \(counts["sms", default: 0])
            WHATSAPP   : \(counts["whatsapp", default: 0])
            CALLS      : \(counts["call", default: 0])
            WARNINGS   : \(warnings.count)
            [!REC]     : \(recoveredCount)
            TIMELINE   : \(timeline.count)
            SMART LINKS: \(smartLinks.count)

            Carpeta del caso:
            \(caseDirectory.path)

            Salida del motor:
            \(processLog)
            """

            renderGallery(
                manifest: manifest,
                artifacts: artifacts,
                databaseAnalysis: databaseAnalysis,
                fileTree: fileTree,
                timeline: timeline,
                smartLinks: smartLinks,
                evidenceQuality: evidenceQuality,
                parserRegistry: parserRegistry,
                statistics: statistics
            )
        } catch {
            summaryView.string = processLog
            setGalleryMessage("No se pudo leer el reporte", detail: error.localizedDescription)
            showError("La adquisición finalizó, pero el reporte no pudo abrirse.")
        }
    }

    private func setRunning(_ running: Bool, status: String) {
        runDemoButton.isEnabled = !running
        acquireButton.isEnabled = !running
        adbButton.isEnabled = !running
        loadReportButton.isEnabled = !running
        whatsAppAnalyzeButton.isEnabled = !running
        carvingButton.isEnabled = !running
        toolkitButton.isEnabled = !running
        navigationButtons.forEach { $0.isEnabled = !running }
        cancelButton.isHidden = !running
        statusLabel.stringValue = status
        statusLabel.textColor = status.contains("FAILED") ? .systemRed : forensicGreen
        if running {
            progressIndicator.startAnimation(nil)
        } else {
            progressIndicator.stopAnimation(nil)
            currentOperationCleansPartials = false
        }
    }

    private func safeCaseURL(_ relativePath: String, under caseDirectory: URL) -> URL? {
        guard !relativePath.isEmpty, !relativePath.hasPrefix("/") else { return nil }
        let components = NSString(string: relativePath).pathComponents
        guard !components.contains("..") else { return nil }
        let root = caseDirectory.standardizedFileURL
        let candidate = root.appendingPathComponent(relativePath).standardizedFileURL
        guard candidate.path == root.path || candidate.path.hasPrefix(root.path + "/") else { return nil }
        return candidate
    }

    private func secureWritableDirectory(_ relativePath: String, under root: URL) throws -> URL {
        guard let candidate = safeCaseURL(relativePath, under: root) else {
            throw NSError(domain: "ForensicMobileLab", code: 40, userInfo: [NSLocalizedDescriptionKey: "Ruta interna inválida."])
        }
        var cursor = root.standardizedFileURL
        for component in NSString(string: relativePath).pathComponents where component != "." {
            cursor.appendPathComponent(component, isDirectory: true)
            if FileManager.default.fileExists(atPath: cursor.path) {
                let values = try cursor.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                guard values.isDirectory == true, values.isSymbolicLink != true else {
                    throw NSError(domain: "ForensicMobileLab", code: 41, userInfo: [NSLocalizedDescriptionKey: "Se detectó un enlace simbólico o un archivo donde debía existir una carpeta."])
                }
            } else {
                try FileManager.default.createDirectory(at: cursor, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            }
        }
        let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL
        let resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
        guard resolved.path.hasPrefix(resolvedRoot.path + "/") else {
            throw NSError(domain: "ForensicMobileLab", code: 42, userInfo: [NSLocalizedDescriptionKey: "La carpeta resuelve fuera del expediente."])
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: resolved.path)
        return resolved
    }

    /// Resolves report-provided paths only when they remain inside the open case.
    /// This prevents a crafted report from previewing arbitrary local Mac files.
    private func manifestFileURL(_ entry: [String: Any], preferThumbnail: Bool = false) -> URL? {
        guard let caseDirectory = currentCaseDirectory else { return nil }
        if preferThumbnail, let thumbnail = entry["thumbnail_path"] as? String,
           let safe = safeExistingCaseFile(thumbnail, under: caseDirectory) {
            return safe
        }
        if let relative = entry["case_relative_path"] as? String,
           let candidate = safeCaseURL(relative, under: caseDirectory),
           let safe = safeExistingCaseFile(candidate.path, under: caseDirectory) {
            return safe
        }
        if let raw = entry["evidence_path"] as? String {
            if let safe = safeExistingCaseFile(raw, under: caseDirectory) { return safe }
            if let legacy = legacyCaseURL(from: raw, under: caseDirectory),
               let safe = safeExistingCaseFile(legacy.path, under: caseDirectory) { return safe }
        }
        return nil
    }

    private func safeExistingCaseFile(_ path: String, under caseDirectory: URL) -> URL? {
        let root = caseDirectory.resolvingSymlinksInPath().standardizedFileURL
        let candidate = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL
        guard candidate.path.hasPrefix(root.path + "/"),
              FileManager.default.fileExists(atPath: candidate.path) else { return nil }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else { return nil }
        return candidate
    }

    private func legacyCaseURL(from absolutePath: String, under caseDirectory: URL) -> URL? {
        // Los informes 3.1 guardaban rutas absolutas. Solo recuperamos subárboles
        // conocidos del expediente y volvemos a aplicar la validación antitraversal.
        let normalized = absolutePath.replacingOccurrences(of: "\\", with: "/")
        for anchor in ["/evidence/", "/recovered_deleted/", "/thumbnails/", "/reports/", "/advanced/"] {
            guard let range = normalized.range(of: anchor, options: .backwards) else { continue }
            let relative = String(normalized[range.lowerBound...].dropFirst())
            if let candidate = safeCaseURL(relative, under: caseDirectory),
               FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    private func showError(_ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Forensic Mobile Lab"
        alert.informativeText = message
        alert.addButton(withTitle: "Aceptar")
        alert.runModal()
    }

    private func casesRoot() -> URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let root = documents.appendingPathComponent("ForensicMobileLabCases", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: root.path
        )
        return root
    }

    private func pythonExecutableURL() -> URL {
        let modernBundled = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/PythonRuntime/bin/python3")
        #if arch(arm64)
        if FileManager.default.isExecutableFile(atPath: modernBundled.path) {
            return modernBundled
        }
        #endif
        let bundled = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/Python3.framework/Versions/Current/bin/python3")
        if FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        // Respaldo para compilaciones de desarrollo que aún no estén empaquetadas.
        return URL(fileURLWithPath: "/usr/bin/python3")
    }

    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private func clock() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: Date())
    }

    private func formattedBytes(_ value: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(value))
    }

    private func renderGallery(
        manifest: [[String: Any]],
        artifacts: [[String: Any]],
        databaseAnalysis: [String: Any],
        fileTree: [String: Any],
        timeline: [[String: Any]],
        smartLinks: [[String: Any]],
        evidenceQuality: [String: Any],
        parserRegistry: [[String: Any]],
        statistics: [String: Any]
    ) {
        let imageExtensions: Set<String> = ["jpg", "jpeg", "png", "heic", "heif", "webp", "gif", "dng"]
        let photos = manifest.filter { evidence in
            guard let path = evidence["evidence_path"] as? String else { return false }
            return imageExtensions.contains(URL(fileURLWithPath: path).pathExtension.lowercased())
                || evidence["thumbnail_path"] is String
        }
        let activePhotos = photos.filter { ($0["is_recovered"] as? Bool) != true }
        let recoveredPhotos = photos.filter { ($0["is_recovered"] as? Bool) == true }
        let multimedia = manifest.filter { item in
            guard let path = item["evidence_path"] as? String else { return false }
            return ["mp4", "mov", "3gp", "m4a", "aac", "ogg", "opus"].contains(URL(fileURLWithPath: path).pathExtension.lowercased())
        }
        let activeMultimedia = multimedia.filter { ($0["is_recovered"] as? Bool) != true }
        let recoveredMultimedia = multimedia.filter { ($0["is_recovered"] as? Bool) == true }

        let activeCards = activePhotos.prefix(250).map { photoCard($0, recovered: false) }.joined()
        let recoveredCards = recoveredPhotos.prefix(250).map { photoCard($0, recovered: true) }.joined()
        let artifactCards = artifacts.prefix(100).map { artifact in
            let type = htmlEscape((artifact["artifact_type"] as? String ?? "artifact").uppercased())
            let source = htmlEscape(artifact["source_database"] as? String ?? "—")
            let record: String
            if let data = try? JSONSerialization.data(withJSONObject: artifact["record"] ?? [:], options: [.prettyPrinted, .sortedKeys]) {
                record = htmlEscape(String(data: data, encoding: .utf8) ?? "{}")
            } else {
                record = "{}"
            }
            return "<article class='artifact'><b>\(type)</b><small>\(source)</small><pre>\(record)</pre></article>"
        }.joined()
        let conversationCards = artifacts.filter {
            let type = $0["artifact_type"] as? String ?? ""
            return type == "sms" || type == "whatsapp"
        }.prefix(500).map { artifact in
            let type = htmlEscape((artifact["artifact_type"] as? String ?? "message").uppercased())
            let record = artifact["record"] as? [String: Any] ?? [:]
            let peer = htmlEscape(String(describing: record["address"] ?? record["key_remote_jid"] ?? "Contacto desconocido"))
            let body = htmlEscape(String(describing: record["body"] ?? record["data"] ?? "[sin texto]"))
            let date = htmlEscape(String(describing: record["date"] ?? record["timestamp"] ?? "—"))
            return "<article class='chat'><div class='avatar'>\(String(type.prefix(1)))</div><div><b>\(peer)</b><p>\(body)</p><small>\(type) · \(date)</small></div></article>"
        }.joined()

        let emptyActive = activePhotos.isEmpty ? "<p class='empty'>No se encontraron fotos activas accesibles.</p>" : ""
        let emptyRecovered = recoveredPhotos.isEmpty ? "<p class='empty'>No se encontraron copias residuales recuperables.</p>" : ""
        let emptyArtifacts = artifacts.isEmpty ? "<p class='empty'>No se detectaron registros SQLite compatibles.</p>" : ""
        let databaseHTML = jsonHTML(databaseAnalysis)
        let treeHTML = jsonHTML(fileTree)
        let timelineHTML = timeline.prefix(250).map { event in
            let timestamp = htmlEscape(event["timestamp"] as? String ?? "—")
            let type = htmlEscape(event["type"] as? String ?? "EVENT")
            let description = htmlEscape(event["description"] as? String ?? "—")
            return "<article class='timeline'><time>\(timestamp)</time><b>\(type)</b><span>\(description)</span></article>"
        }.joined()
        let linksHTML = smartLinks.prefix(500).map { link in
            let file = htmlEscape(link["recovered_file"] as? String ?? "—")
            let source = htmlEscape(link["message_source"] as? String ?? "—")
            let hash = htmlEscape(link["file_hash"] as? String ?? "—")
            return "<article class='link'><b>VERIFIED TEXT MATCH</b><span>Mensaje: \(source)</span><span>Archivo: \(file)</span><small>SHA-256: \(hash)</small></article>"
        }.joined()
        let emptyTimeline = timeline.isEmpty ? "<p class='empty'>No hay eventos con fecha.</p>" : ""
        let emptyLinks = smartLinks.isEmpty ? "<p class='empty'>No se encontraron referencias textuales verificables.</p>" : ""
        func mediaCards(_ items: [[String: Any]], recovered: Bool) -> String {
            items.map { item in
            let rawPath = item["evidence_path"] as? String ?? "—"
            let path = htmlEscape(rawPath)
            guard let safeURL = manifestFileURL(item) else {
                return "<article class='artifact'><b>MEDIA NO DISPONIBLE</b><small>La ruta no pertenece al expediente abierto.</small><small>\(path)</small></article>"
            }
            let fileURL = safeURL.absoluteString
            let ext = URL(fileURLWithPath: rawPath).pathExtension.lowercased()
            let player = ["mp4", "mov", "3gp"].contains(ext)
                ? "<video controls preload='metadata' src='\(htmlEscape(fileURL))'></video>"
                : "<audio controls preload='metadata' src='\(htmlEscape(fileURL))'></audio>"
            let name = htmlEscape(URL(fileURLWithPath: rawPath).lastPathComponent)
            let hash = htmlEscape(item["sha256"] as? String ?? "—")
            let openURL = "forensic://open?path=\(safeURL.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")"
            let badge = recovered ? "<span class='badge'>!REC MULTIMEDIA</span>" : "<span class='status-media'>ACTIVO</span>"
            let className = recovered ? "artifact media-recovered" : "artifact media-active"
            return "<article class='\(className)'>\(badge)<b>MEDIA · \(name)</b>\(player)<a class='annotate' href='\(openURL)'>ABRIR EXTERNAMENTE</a><small>\(path)</small><small>SHA-256: \(hash)</small></article>"
            }.joined()
        }
        let activeMediaHTML = mediaCards(Array(activeMultimedia.prefix(100)), recovered: false)
        let recoveredMediaHTML = mediaCards(Array(recoveredMultimedia.prefix(100)), recovered: true)
        let qualityHTML = jsonHTML(evidenceQuality)
        let parsersHTML = jsonHTML(parserRegistry)
        let statisticsHTML = jsonHTML(statistics)
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><style>
        :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:22px;background:radial-gradient(circle at 20% 0,#122631 0,#0b1117 42%,#080c11 100%);color:#e5f4f7;font:13px -apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif}
        header{position:sticky;top:0;z-index:3;background:rgba(19,31,39,.92);border:1px solid rgba(89,217,245,.35);border-radius:16px;padding:16px 18px;margin-bottom:22px;backdrop-filter:blur(18px);box-shadow:0 14px 35px #0006}.tools{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}.tools button,.tools input{border:1px solid #365660;background:#122129;color:#dff4f6;border-radius:8px;padding:7px 10px}.tools button{cursor:pointer}.tools button:hover{border-color:#59d9f5}.tools input{min-width:220px}
        h1{font-size:19px;color:#fff;margin:0 0 6px;letter-spacing:.02em}h2{font-size:13px;letter-spacing:.1em;margin:30px 0 14px;color:#59d9f5;border-bottom:1px solid #29434d;padding-bottom:9px}.recovered-title{color:#ff6b70;border-color:#683338}
        .count{color:#99adb4}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(205px,1fr));gap:16px}.card{cursor:pointer;overflow:hidden;background:linear-gradient(145deg,rgba(31,48,57,.96),rgba(18,27,34,.96));border:1px solid rgba(100,176,200,.25);border-radius:15px;box-shadow:0 12px 30px #0007;transition:transform .18s,border-color .18s}.card:hover{transform:translateY(-3px);border-color:#59d9f5}.card.recovered{border-color:#9b4549}.card img{display:block;width:100%;height:175px;object-fit:contain;background:#080c10}.meta{padding:12px}.name{font-weight:700;color:#65e8a0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.recovered .name{color:#ff7378}.meta small{display:block;color:#90a6ad;margin-top:6px;word-break:break-all}.annotate{display:inline-block;margin-top:9px;padding:6px 9px;background:#285a68;color:#dff8fb;border-radius:7px;text-decoration:none;font-weight:700}.badge,.status-media{display:inline-block;border-radius:999px;padding:3px 8px;margin:0 8px 7px 0;font-weight:700}.badge{background:#70262b;color:#ffc0c2}.status-media{background:#17463c;color:#75efb4}.empty{padding:28px;border:1px dashed #38535e;border-radius:12px;color:#82979b;text-align:center;background:#111a2080}.artifact{background:#121e25cc;border:1px solid #263d47;border-left:3px solid #59d9f5;padding:12px;margin:10px 0;border-radius:10px}.media-recovered{border-color:#71373b;border-left-color:#ff6b70;background:#211719}.artifact video{display:block;max-width:640px;width:100%;max-height:360px;margin:12px 0;background:#05080a}.artifact audio{display:block;width:min(640px,100%);margin:12px 0}.artifact small{display:block;color:#81969b;margin:5px 0}.artifact pre,.json{white-space:pre-wrap;word-break:break-word;color:#c5dce1;font:11px "SF Mono",monospace;background:#0d151acc;padding:14px;border-radius:10px}.chat{display:flex;gap:12px;max-width:760px;margin:10px 0;padding:13px;background:#152831;border:1px solid #2c4e59;border-radius:14px}.chat .avatar{width:34px;height:34px;flex:0 0 34px;border-radius:50%;display:grid;place-items:center;background:#2b9db3;font-weight:900}.chat p{margin:6px 0;color:#d7e8eb}.chat small{color:#839ba1}.timeline{position:relative;display:grid;grid-template-columns:190px 145px 1fr;gap:10px;padding:12px 12px 12px 22px;border-left:3px solid #2f8597;border-bottom:1px solid #26373b;background:#10191f80}.timeline:before{content:'';position:absolute;left:-7px;top:17px;width:10px;height:10px;border-radius:50%;background:#59d9f5}.timeline time{color:#8fa5aa}.timeline b{color:#59d9f5}.link{display:flex;flex-direction:column;gap:6px;background:#241719;border:1px solid #71373b;padding:12px;margin:9px 0;border-radius:11px}.link b{color:#ff7378}.link small{color:#9baeb2}.modal{display:none;position:fixed;inset:0;z-index:20;background:#020507eF;padding:35px}.modal.open{display:flex;gap:24px;align-items:center;justify-content:center}.modal img{max-width:70%;max-height:90%;object-fit:contain}.modal .details{max-width:330px;color:#d7eaed;word-break:break-word;max-height:85%;overflow:auto}.close{position:absolute;right:25px;top:20px;color:#fff;font-size:30px;cursor:pointer}
        </style></head><body>
        <header><h1>FORENSIC PHOTO GALLERY</h1><span class="count">Activas: \(activePhotos.count) &nbsp;•&nbsp; [!REC] Recuperadas: \(recoveredPhotos.count) &nbsp;•&nbsp; Artefactos: \(artifacts.count)</span><div class="tools"><button onclick="filterCards('all')">Todas</button><button onclick="filterCards('active')">Activas</button><button onclick="filterCards('recovered')">[!REC]</button><input id="search" placeholder="Búsqueda global: fotos, mensajes, rutas…" oninput="globalSearch(this.value)"></div></header>
        <h2 id="gallery">FOTOS ACTIVAS · mostrando \(min(activePhotos.count, 250)) de \(activePhotos.count)</h2><section class="grid">\(activeCards)</section>\(emptyActive)
        <h2 id="recovery" class="recovered-title">[!REC] FOTOS RECUPERADAS · mostrando \(min(recoveredPhotos.count, 250)) de \(recoveredPhotos.count)</h2><section class="grid">\(recoveredCards)</section>\(emptyRecovered)
        <h2 id="sql">ARTEFACTOS SQLITE · mostrando \(min(artifacts.count, 100)) de \(artifacts.count)</h2>\(artifactCards)\(emptyArtifacts)
        <h2 id="conversations">VISOR DE CONVERSACIONES · máximo 500; consulta completa en FTS5</h2>\(conversationCards.isEmpty ? "<p class='empty'>No hay mensajes compatibles.</p>" : conversationCards)
        <h2 id="multimedia">MULTIMEDIA ACTIVA · mostrando \(min(activeMultimedia.count, 100)) de \(activeMultimedia.count)</h2>\(activeMediaHTML.isEmpty ? "<p class='empty'>No se adquirieron videos ni audios activos.</p>" : activeMediaHTML)
        <h2 class="recovered-title">[!REC] MULTIMEDIA RECUPERADA · mostrando \(min(recoveredMultimedia.count, 100)) de \(recoveredMultimedia.count)</h2>\(recoveredMediaHTML.isEmpty ? "<p class='empty'>No se encontraron videos o audios residuales recuperables.</p>" : recoveredMediaHTML)
        <h2>CALIDAD DE EVIDENCIA</h2><pre class="json">\(qualityHTML)</pre>
        <h2>REGISTRO DE PARSERS</h2><pre class="json">\(parsersHTML)</pre>
        <h2>ESTADÍSTICAS DESCRIPTIVAS</h2><pre class="json">\(statisticsHTML)</pre>
        <h2 id="report">ANÁLISIS DE BASES DE DATOS</h2><pre class="json">\(databaseHTML)</pre>
        <h2 id="filesystem">ÁRBOL LÓGICO DE ARCHIVOS</h2><pre class="json">\(treeHTML)</pre>
        <h2 id="timeline">TIMELINE UNIFICADO</h2>\(timelineHTML)\(emptyTimeline)
        <h2 id="links" class="recovered-title">SMART LINKS</h2>\(linksHTML)\(emptyLinks)
        <div id="modal" class="modal" onclick="if(event.target===this)closePhoto()"><span class="close" onclick="closePhoto()">×</span><img id="modalImage"><div id="modalDetails" class="details"></div></div>
        <script>function cards(){return [...document.querySelectorAll('.card')]}function filterCards(k){cards().forEach(c=>c.style.display=(k==='all'||c.classList.contains(k))?'':'none')}function globalSearch(q){q=q.toLowerCase();document.querySelectorAll('.card,.chat,.artifact,.timeline,.link').forEach(c=>c.style.display=c.innerText.toLowerCase().includes(q)?'':'none')}function openPhoto(c){document.getElementById('modalImage').src=c.querySelector('img').src;document.getElementById('modalDetails').innerHTML=c.querySelector('.meta').innerHTML;document.getElementById('modal').classList.add('open')}function closePhoto(){document.getElementById('modal').classList.remove('open')}document.addEventListener('keydown',e=>{if(e.key==='Escape')closePhoto()})</script></body></html>
        """
        if let caseDirectory = currentCaseDirectory {
            // Caché de presentación: queda fuera del manifiesto probatorio y puede regenerarse.
            let uiDirectory = caseDirectory.appendingPathComponent(".ui_cache", isDirectory: true)
            let htmlFile = uiDirectory.appendingPathComponent("ui_gallery.html")
            do {
                try FileManager.default.createDirectory(at: uiDirectory, withIntermediateDirectories: true)
                try Data(html.utf8).write(to: htmlFile, options: .atomic)
                galleryWebView.loadFileURL(htmlFile, allowingReadAccessTo: caseDirectory)
            } catch {
                galleryWebView.loadHTMLString(html, baseURL: caseDirectory)
            }
        } else {
            galleryWebView.loadHTMLString(html, baseURL: nil)
        }
    }

    private func photoCard(_ evidence: [String: Any], recovered: Bool) -> String {
        guard let localPath = evidence["evidence_path"] as? String else { return "" }
        guard let imageURL = manifestFileURL(evidence, preferThumbnail: true) else {
            return photoPlaceholderCard(evidence, recovered: recovered)
        }
        let previewSize = (try? imageURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? Int.max
        guard previewSize <= 5 * 1024 * 1024,
              let imageData = try? Data(contentsOf: imageURL, options: [.mappedIfSafe]) else {
            return photoPlaceholderCard(evidence, recovered: recovered)
        }
        let imageSource = "data:image/jpeg;base64,\(imageData.base64EncodedString())"
        let remotePath = evidence["logical_path"] as? String ?? localPath
        let name = htmlEscape(URL(fileURLWithPath: remotePath).lastPathComponent)
        let size = formattedBytes(evidence["size"] as? Int ?? 0)
        let sha = htmlEscape(evidence["sha256"] as? String ?? "—")
        let exif = jsonHTML(evidence["exif_metadata"] ?? [:])
        let recoveredBadge = recovered ? "<span class='badge'>!REC</span>" : ""
        let annotationURL = "forensic://annotate?hash=\(sha.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")&path=\(remotePath.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")"
        let cardClass = recovered ? "card recovered" : "card"
        return "<article class='\(cardClass) \(recovered ? "recovered" : "active")' onclick='openPhoto(this)'><img loading='lazy' src='\(imageSource)' alt='\(name)'><div class='meta'>\(recoveredBadge)<div class='name'>\(name)</div><small>\(htmlEscape(size))</small><small>SHA-256: \(sha)</small><small>\(htmlEscape(remotePath))</small><small>Local: \(htmlEscape(localPath))</small><small>EXIF / GPS:<br>\(exif)</small><a class='annotate' href='\(annotationURL)' onclick='event.stopPropagation()'>MARCAR / ANOTAR</a></div></article>"
    }

    private func photoPlaceholderCard(_ evidence: [String: Any], recovered: Bool) -> String {
        let remotePath = evidence["logical_path"] as? String ?? "Archivo sin nombre"
        let name = htmlEscape(URL(fileURLWithPath: remotePath).lastPathComponent)
        let sha = htmlEscape(evidence["sha256"] as? String ?? "—")
        let marker = recovered ? "<span class='badge'>!REC</span>" : ""
        let cardClass = recovered ? "card recovered" : "card active"
        return "<article class='\(cardClass)'><div style='height:175px;display:grid;place-items:center;background:#10171b;color:#71858b'>VISTA PREVIA NO DISPONIBLE</div><div class='meta'>\(marker)<div class='name'>\(name)</div><small>SHA-256: \(sha)</small><small>\(htmlEscape(remotePath))</small></div></article>"
    }

    private func setGalleryMessage(_ title: String, detail: String) {
        let html = """
        <html><head><meta charset="utf-8"><style>:root{color-scheme:dark}body{background:#0d1113;color:#8ea3a8;font:14px -apple-system;padding:40px;text-align:center}h2{color:#35f27a}</style></head>
        <body><h2>\(htmlEscape(title))</h2><p>\(htmlEscape(detail))</p></body></html>
        """
        galleryWebView.loadHTMLString(html, baseURL: nil)
    }

    private func htmlEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    private func jsonHTML(_ object: Any) -> String {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(
                withJSONObject: object,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let text = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return htmlEscape(text)
    }
}

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
