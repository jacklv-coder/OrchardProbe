import DemoFramework
import Foundation
import SwiftUI
import UniformTypeIdentifiers
import UIKit

@main
struct DemoLabApp: App {
    init() {
        oprobe_main_anchor()
    }

    var body: some Scene {
        WindowGroup {
            LAB002WorkflowView()
        }
    }
}

private struct LAB002WorkflowView: View {
    @StateObject private var model = LAB002WorkflowModel()
    @State private var importsAuthorization = false
    @State private var confirmsCleanup = false

    private let frameworkMessage = DLDemoMessage.fixedString()

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    statusCard
                    authorizationSection
                    operationSection
                    exportSection
                    safetyNote
                }
                .padding(20)
            }
            .navigationTitle("DemoLab")
            .fileImporter(
                isPresented: $importsAuthorization,
                allowedContentTypes: [.json],
                allowsMultipleSelection: false
            ) { result in
                model.importAuthorization(result)
            }
            .sheet(isPresented: $model.presentsRoleInvocation) {
                LAB002RoleInvocationShareSheet()
                    .ignoresSafeArea()
            }
            .sheet(isPresented: $model.presentsArtifact) {
                if let artifact = model.artifact {
                    LAB002SystemShareSheet(artifact: artifact)
                        .ignoresSafeArea()
                }
            }
            .alert(
                "Clean completed reports?",
                isPresented: $confirmsCleanup
            ) {
                Button("Cancel", role: .cancel) {}
                Button("I received the export", role: .destructive) {
                    model.cleanExportedReports()
                }
            } message: {
                Text(
                    "Only continue after the exported JSON is safely " +
                        "stored outside DemoLab. This removes the completed " +
                        "on-device report subtree."
                )
            }
        }
        .navigationViewStyle(.stack)
        .task {
            model.restoreWorkflow()
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 38))
                .foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 3) {
                Text("OrchardProbe LAB-002")
                    .font(.title2.bold())
                Text(frameworkMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var statusCard: some View {
        HStack(alignment: .top, spacing: 12) {
            if model.isBusy {
                ProgressView()
            } else {
                Image(systemName: model.statusSymbol)
                    .foregroundStyle(model.hasError ? .red : .green)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(model.statusTitle)
                    .font(.headline)
                Text(model.statusDetail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            (model.hasError ? Color.red : Color.green).opacity(0.1),
            in: RoundedRectangle(cornerRadius: 14)
        )
    }

    private var authorizationSection: some View {
        LAB002WorkflowSection(
            number: 1,
            title: "Import Host authorization",
            detail:
                "Choose the signed JSON supplied for this exact DemoLab build."
        ) {
            Button {
                importsAuthorization = true
            } label: {
                Label("Choose authorization JSON", systemImage: "doc.badge.plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.canImportAuthorization)

            if model.canDiscardAuthorization {
                Button(role: .destructive) {
                    model.discardInvalidAuthorization()
                } label: {
                    Label(
                        "Discard unusable authorization",
                        systemImage: "trash"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(model.isBusy)
            }
        }
    }

    private var operationSection: some View {
        LAB002WorkflowSection(
            number: 2,
            title: model.operationTitle,
            detail: model.operationDetail
        ) {
            switch model.authorizationKind {
            case .none:
                Text("Import a valid authorization to unlock this step.")
                    .foregroundStyle(.secondary)
            case .enrollment:
                Button {
                    model.confirmEnrollment()
                } label: {
                    Label(
                        "Confirm enrollment and export receipt",
                        systemImage: "checkmark.shield"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy)
            case .run:
                VStack(spacing: 12) {
                    Button {
                        model.startRun()
                    } label: {
                        Label(
                            "Start clean run",
                            systemImage: "play.fill"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isBusy || model.runStarted)

                    Button {
                        model.presentsRoleInvocation = true
                    } label: {
                        Label(
                            "Open Share panel and choose DemoLab Share",
                            systemImage: "square.and.arrow.up"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(
                        model.isBusy
                            || !model.runStarted
                            || model.canCleanReports
                            || model.isTerminalFailure
                    )

                    Text(
                        "In the system panel, tap “DemoLab Share”, wait for " +
                            "its success message, then tap Done and return here."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var exportSection: some View {
        LAB002WorkflowSection(
            number: 3,
            title: "Export and explicit cleanup",
            detail:
                "Evidence leaves the app only through the system share panel."
        ) {
            VStack(spacing: 12) {
                if let fingerprint =
                    model.deviceSelectionFingerprintDisplay
                {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Device-selection fingerprint")
                            .font(.caption.bold())
                        Text(fingerprint)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(
                        Color.orange.opacity(0.12),
                        in: RoundedRectangle(cornerRadius: 10)
                    )
                }

                if model.authorizationKind == .run {
                    Button {
                        model.completeAndExportRun()
                    } label: {
                        Label(
                            "Complete run and export evidence",
                            systemImage: "doc.badge.checkmark"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        model.isBusy
                            || !model.runStarted
                            || model.canCleanReports
                            || model.isTerminalFailure
                    )
                }

                Button {
                    model.presentsArtifact = true
                } label: {
                    Label(
                        "Share generated JSON again",
                        systemImage: "arrow.up.doc"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(model.isBusy || model.artifact == nil)

                if model.requiresEnrollmentReceiptSaveConfirmation {
                    Button {
                        model.confirmEnrollmentReceiptSaved()
                    } label: {
                        Label(
                            "I saved the enrollment receipt",
                            systemImage: "checkmark.shield"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isBusy)

                    Text(
                        "Run authorization stays locked until you explicitly " +
                            "confirm that the enrollment receipt is stored " +
                            "outside DemoLab."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                if model.canCleanReports {
                    Button(role: .destructive) {
                        confirmsCleanup = true
                    } label: {
                        Label(
                            "Confirm receipt and clean reports",
                            systemImage: "trash"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(model.isBusy)
                }
            }
        }
    }

    private var safetyNote: some View {
        Text(
            "First-party research fixture only. DemoLab never reads installed " +
                "third-party apps, bypasses DRM, re-signs, or redistributes " +
                "applications."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.top, 4)
    }
}

private struct LAB002WorkflowSection<Content: View>: View {
    let number: Int
    let title: String
    let detail: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("\(number)")
                    .font(.caption.bold())
                    .foregroundStyle(.white)
                    .frame(width: 24, height: 24)
                    .background(.green, in: Circle())
                Text(title)
                    .font(.headline)
            }
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            Color(uiColor: .secondarySystemBackground),
            in: RoundedRectangle(cornerRadius: 14)
        )
    }
}

enum LAB002WorkflowSafety {
    static func permitsAuthorizationImport(
        baseConditionsSatisfied: Bool,
        hasUnconfirmedEnrollmentReceipt: Bool
    ) -> Bool {
        baseConditionsSatisfied && !hasUnconfirmedEnrollmentReceipt
    }

    static func requiresTerminalFailure(
        terminalOnFailure: Bool,
        recoverySucceeded: Bool
    ) -> Bool {
        terminalOnFailure || !recoverySucceeded
    }
}

@MainActor
private final class LAB002WorkflowModel: ObservableObject {
    enum AuthorizationKind: Equatable {
        case none
        case enrollment
        case run
    }

    @Published var authorizationKind: AuthorizationKind = .none
    @Published var artifact: LAB002ShareArtifact?
    @Published var isBusy = false
    @Published var hasError = false
    @Published var statusTitle = "Ready"
    @Published var statusDetail =
        "Import a signed Host authorization to begin."
    @Published var runStarted = false
    @Published var canCleanReports = false
    @Published var canDiscardAuthorization = false
    @Published var presentsArtifact = false
    @Published var presentsRoleInvocation = false
    @Published var deviceSelectionFingerprintSHA256: String?
    @Published var isTerminalFailure = false
    @Published private(set) var enrollmentReceiptSaveConfirmed = false

    private let coordinator: LAB002InboxCoordinator?
    private var didRestoreWorkflow = false

    init() {
        do {
            let validator = try LAB002ProductionAuthorizationValidator()
            coordinator = try LAB002InboxCoordinator(validator: validator)
        } catch {
            coordinator = nil
            hasError = true
            statusTitle = "Build is not configured for LAB-002"
            statusDetail =
                "The signed archive must inject the fixed build binding, " +
                "identity nonce, App Group, and authorization public key."
        }
    }

    var isConfigured: Bool {
        coordinator != nil
    }

    var canImportAuthorization: Bool {
        LAB002WorkflowSafety.permitsAuthorizationImport(
            baseConditionsSatisfied:
                isConfigured
                && !isBusy
                && authorizationKind == .none
                && !runStarted
                && !canCleanReports
                && !canDiscardAuthorization
                && !isTerminalFailure,
            hasUnconfirmedEnrollmentReceipt:
                requiresEnrollmentReceiptSaveConfirmation
        )
    }

    var requiresEnrollmentReceiptSaveConfirmation: Bool {
        artifact?.kind == .enrollmentReceipt
            && !enrollmentReceiptSaveConfirmed
    }

    var statusSymbol: String {
        hasError ? "xmark.octagon.fill" : "checkmark.circle.fill"
    }

    var operationTitle: String {
        switch authorizationKind {
        case .none:
            return "Perform authorized operation"
        case .enrollment:
            return "Enroll this installation"
        case .run:
            return "Collect one fixed-range run"
        }
    }

    var operationDetail: String {
        switch authorizationKind {
        case .none:
            return "The signed authorization selects the only allowed path."
        case .enrollment:
            return
                "Create this build’s device-bound enrollment key and receipt."
        case .run:
            return
                "Observe the app, framework, and share extension in fixed order."
        }
    }

    var deviceSelectionFingerprintDisplay: String? {
        guard let value = deviceSelectionFingerprintSHA256 else {
            return nil
        }
        let bytes = Array(value.utf8)
        return stride(from: 0, to: bytes.count, by: 4)
            .map {
                String(
                    decoding: bytes[$0..<min($0 + 4, bytes.count)],
                    as: UTF8.self
                )
            }
            .joined(separator: " ")
    }

    func restoreWorkflow() {
        guard !didRestoreWorkflow, let coordinator else { return }
        didRestoreWorkflow = true
        runTask(
            title: "Restoring fixed workflow",
            terminalOnFailure: true
        ) {
            let state = try await coordinator.recoverWorkflowState()
            try await self.applyRecoveryState(
                state,
                coordinator: coordinator,
                updateStatus: true
            )
        }
    }

    func importAuthorization(
        _ result: Result<[URL], Error>
    ) {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        guard canImportAuthorization else {
            hasError = true
            statusTitle = "Authorization import is locked"
            statusDetail =
                "Save and confirm the enrollment receipt before importing " +
                "a run authorization."
            return
        }
        do {
            let url = try result.get().onlyElement()
            runTask(title: "Importing authorization") {
                let accessed = url.startAccessingSecurityScopedResource()
                defer {
                    if accessed {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                let metadata = try await coordinator.importAuthorization(
                    from: url
                )
                let state = try await coordinator.recoverWorkflowState()
                try await self.applyRecoveryState(
                    state,
                    coordinator: coordinator,
                    updateStatus: false
                )
                if state == .discardableAuthorization {
                    self.hasError = true
                    self.statusTitle = "Authorization cannot be used"
                    self.statusDetail =
                        "Discard this unusable authorization before " +
                        "importing the one required by the current state."
                } else {
                    self.statusTitle = "Authorization imported"
                    self.statusDetail = metadata.kind
                        == .installationEnrollment
                        ? "Ready to enroll this exact installation."
                        : "Ready to collect the authorized run."
                }
            }
        } catch {
            report(error, title: "Authorization was not selected")
        }
    }

    func confirmEnrollment() {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        runTask(title: "Confirming enrollment") {
            let completion =
                try await coordinator.confirmInstallationEnrollment()
            self.artifact = completion.receipt
            self.enrollmentReceiptSaveConfirmed = false
            self.deviceSelectionFingerprintSHA256 =
                completion.deviceSelectionFingerprintSHA256
            self.authorizationKind = .none
            self.statusTitle = "Enrollment receipt created"
            self.statusDetail =
                "Compare the full fingerprint with the Host, then save " +
                "the receipt before importing a run."
            self.presentsArtifact = true
        }
    }

    func confirmEnrollmentReceiptSaved() {
        guard artifact?.kind == .enrollmentReceipt,
              !isBusy,
              !isTerminalFailure
        else {
            return
        }
        enrollmentReceiptSaveConfirmed = true
        statusTitle = "Enrollment receipt confirmed"
        statusDetail =
            "The receipt remains shareable here. You may now import the " +
            "first signed run authorization."
    }

    func startRun() {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        runTask(title: "Starting clean run") {
            _ = try await coordinator.startCleanRun()
            self.runStarted = true
            self.statusTitle = "App and framework observed"
            self.statusDetail =
                "Now open the Share panel and choose DemoLab Share."
        }
    }

    func completeAndExportRun() {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        runTask(title: "Completing and exporting run") {
            let outcome =
                try await coordinator.completeRunAfterShareExtension()
            guard outcome == .committed else {
                self.enterTerminalFailure(
                    title: "Run completion is durability-uncertain",
                    detail:
                        "The session commit could not be confirmed durable. " +
                        "This exact experiment is No-Go and cannot be exported " +
                        "or retried."
                )
                return
            }
            let artifact = try await coordinator.exportLAB002Evidence()
            self.artifact = artifact
            self.canCleanReports = true
            self.statusTitle = "Session evidence created"
            self.statusDetail =
                "Save the JSON outside DemoLab, then explicitly clean reports."
            self.presentsArtifact = true
        }
    }

    func cleanExportedReports() {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        runTask(title: "Cleaning completed reports") {
            let outcome = try await coordinator
                .confirmExportReceivedAndCleanReports(confirmed: true)
            guard outcome == .cleaned else {
                self.enterTerminalFailure(
                    title: "Report cleanup is durability-uncertain",
                    detail:
                        "Cleanup may have partially committed. This exact " +
                        "experiment remains No-Go; do not retry cleanup or " +
                        "start another run in this installation."
                )
                return
            }
            self.canCleanReports = false
            self.runStarted = false
            self.authorizationKind = .none
            self.statusTitle = "Completed reports cleaned"
            self.statusDetail =
                "The exported JSON remains under your control outside DemoLab."
        }
    }

    func discardInvalidAuthorization() {
        guard let coordinator else {
            reportConfigurationError()
            return
        }
        runTask(title: "Discarding unusable authorization") {
            _ = try await coordinator.discardStaleAuthorization()
            self.authorizationKind = .none
            self.artifact = nil
            self.runStarted = false
            self.canCleanReports = false
            self.canDiscardAuthorization = false
            self.statusTitle = "Authorization discarded"
            self.statusDetail =
                "You may now import a fresh authorization for this build."
        }
    }

    private func runTask(
        title: String,
        terminalOnFailure: Bool = false,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        guard !isBusy else { return }
        isBusy = true
        hasError = false
        statusTitle = title
        Task {
            do {
                try await operation()
                isBusy = false
            } catch {
                let operationError = error
                var recoverySucceeded = false
                if let coordinator {
                    do {
                        try await self.recoverDurableState(
                            coordinator: coordinator,
                            updateStatus: false
                        )
                        recoverySucceeded = true
                    } catch {
                        recoverySucceeded = false
                    }
                }
                isBusy = false
                if LAB002WorkflowSafety.requiresTerminalFailure(
                    terminalOnFailure: terminalOnFailure,
                    recoverySucceeded: recoverySucceeded
                ) {
                    enterTerminalFailure(
                        title: "Workflow recovery failed closed",
                        detail:
                            "Durable LAB-002 state is missing, uncertain, " +
                            "or conflicting. This installation cannot " +
                            "continue the experiment."
                    )
                } else {
                    report(operationError, title: "Operation failed closed")
                }
            }
        }
    }

    private func recoverDurableState(
        coordinator: LAB002InboxCoordinator,
        updateStatus: Bool
    ) async throws {
        let state = try await coordinator.recoverWorkflowState()
        try await applyRecoveryState(
            state,
            coordinator: coordinator,
            updateStatus: updateStatus
        )
    }

    private func applyRecoveryState(
        _ state: LAB002WorkflowRecoveryState,
        coordinator: LAB002InboxCoordinator,
        updateStatus: Bool
    ) async throws {
        canDiscardAuthorization = false
        deviceSelectionFingerprintSHA256 = nil
        isTerminalFailure = false
        switch state {
        case .ready:
            authorizationKind = .none
            artifact = nil
            enrollmentReceiptSaveConfirmed = false
            runStarted = false
            canCleanReports = false
            if updateStatus {
                statusTitle = "Ready"
                statusDetail = "Import a signed Host authorization to begin."
            }
        case let .enrollmentReceipt(receipt, fingerprintSHA256):
            authorizationKind = .none
            artifact = receipt
            enrollmentReceiptSaveConfirmed = false
            deviceSelectionFingerprintSHA256 = fingerprintSHA256
            runStarted = false
            canCleanReports = false
            if updateStatus {
                statusTitle = "Enrollment receipt restored"
                statusDetail =
                    "Compare the full fingerprint with the Host, then save " +
                    "the receipt before importing a run."
            }
        case let .pendingAuthorization(kind):
            authorizationKind = kind == .installationEnrollment
                ? .enrollment : .run
            artifact = nil
            enrollmentReceiptSaveConfirmed = false
            runStarted = false
            canCleanReports = false
            if updateStatus {
                statusTitle = "Authorization restored"
                statusDetail = kind == .installationEnrollment
                    ? "Resume enrollment for this exact installation."
                    : "Resume the authorized run."
            }
        case .discardableAuthorization:
            authorizationKind = .none
            artifact = nil
            enrollmentReceiptSaveConfirmed = false
            runStarted = false
            canCleanReports = false
            canDiscardAuthorization = true
            if updateStatus {
                hasError = true
                statusTitle = "Unusable authorization restored"
                statusDetail =
                    "Discard it before importing the authorization required " +
                    "for the current enrollment state."
            }
        case .runInProgress:
            authorizationKind = .run
            artifact = nil
            enrollmentReceiptSaveConfirmed = false
            runStarted = true
            canCleanReports = false
            if updateStatus {
                statusTitle = "Run restored"
                statusDetail =
                    "Open the Share panel, choose DemoLab Share, then export."
            }
        case .completedRun:
            authorizationKind = .run
            runStarted = true
            artifact = try await coordinator.exportLAB002Evidence()
            enrollmentReceiptSaveConfirmed = false
            canCleanReports = true
            if updateStatus {
                statusTitle = "Completed evidence restored"
                statusDetail =
                    "Share the JSON again, then explicitly confirm cleanup."
            }
        case .failedRun:
            authorizationKind = .none
            artifact = nil
            enrollmentReceiptSaveConfirmed = false
            runStarted = true
            canCleanReports = false
            isTerminalFailure = true
            if updateStatus {
                hasError = true
                statusTitle = "Persisted run failed closed"
                statusDetail =
                    "This experiment cannot be retried or cleaned into a pass."
            }
        }
    }

    private func enterTerminalFailure(
        title: String,
        detail: String
    ) {
        isTerminalFailure = true
        hasError = true
        authorizationKind = .none
        runStarted = true
        canCleanReports = false
        canDiscardAuthorization = false
        statusTitle = title
        statusDetail = detail
    }

    private func reportConfigurationError() {
        hasError = true
        statusTitle = "Build is not configured for LAB-002"
        statusDetail =
            "Use a reviewed signed archive with all fixed LAB-002 inputs."
    }

    private func report(_ error: Error, title: String) {
        hasError = true
        statusTitle = title
        statusDetail = String(describing: error)
    }
}

private struct LAB002RoleInvocationShareSheet:
    UIViewControllerRepresentable
{
    func makeUIViewController(
        context: Context
    ) -> UIActivityViewController {
        let controller = UIActivityViewController(
            activityItems: [
                "OrchardProbe LAB-002 fixed share-extension observation"
            ],
            applicationActivities: nil
        )
        if let popover = controller.popoverPresentationController {
            popover.sourceView = controller.view
            popover.sourceRect = CGRect(
                x: controller.view.bounds.midX,
                y: controller.view.bounds.midY,
                width: 1,
                height: 1
            )
            popover.permittedArrowDirections = []
        }
        return controller
    }

    func updateUIViewController(
        _ uiViewController: UIActivityViewController,
        context: Context
    ) {}
}

private extension Collection {
    func onlyElement() throws -> Element {
        guard count == 1, let element = first else {
            throw LAB002AuthorizationValidationError.invalidEnvelope
        }
        return element
    }
}
