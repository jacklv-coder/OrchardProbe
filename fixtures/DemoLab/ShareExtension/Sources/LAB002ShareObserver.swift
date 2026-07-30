import Foundation

func observeCurrentShareExecutable() throws {
    let observation = try LAB002LiveMachOObserver.observe(
        fixedBundle: .main,
        compiledAnchor: unsafeBitCast(
            oprobe_share_anchor as @convention(c) () -> Void,
            to: UnsafeRawPointer.self
        ),
        fixedRole: .shareExtension
    )
    try LAB002RoleReportPublisher.publish(
        observation,
        fixedBundle: .main,
        fixedRole: .shareExtension
    )
}
