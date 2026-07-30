import Foundation

enum LAB002FixedName {
    static let root = "lab-002-v1"
    static let lock = "coordinator.lock"
    static let inbox = "inbox"
    static let authorization = "authorization-v1.json"
    static let authorizationTemporary = "authorization-v1.json.tmp"
    static let authorizationQuarantine = "authorization-quarantine-v1.json"
    static let state = "state"
    static let installationNonce = "installation-nonce-v1.json"
    static let installationNonceTemporary = "installation-nonce-v1.json.tmp"
    static let counter = "run-counter-v1.json"
    static let counterTemporary = "run-counter-v1.json.tmp"
    static let reports = "reports"
    static let currentReports = "current"
    static let session = "session.json"
    static let sessionTemporary = "session.json.tmp"
    static let mainAppReport = "main-app.json"
    static let mainAppReportTemporary = "main-app.json.tmp"
    static let frameworkReport = "framework.json"
    static let frameworkReportTemporary = "framework.json.tmp"
    static let shareExtensionReport = "share-extension.json"
    static let shareExtensionReportTemporary = "share-extension.json.tmp"
}

enum LAB002Limit {
    static let controlDocument = 16 * 1024
    static let fixedState = 1024
    static let sessionReport = 16 * 1024
    static let roleReport = 32 * 1024
    static let signedExport = 512 * 1024
}
