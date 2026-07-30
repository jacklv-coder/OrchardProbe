import Foundation

func observeCurrentMainExecutable() throws {
    let observation = try LAB002LiveMachOObserver.observe(
        fixedBundle: .main,
        compiledAnchor: unsafeBitCast(
            oprobe_main_anchor as @convention(c) () -> Void,
            to: UnsafeRawPointer.self
        ),
        fixedRole: .mainApp
    )
    try LAB002RoleReportPublisher.publish(
        observation,
        fixedBundle: .main,
        fixedRole: .mainApp
    )
}
