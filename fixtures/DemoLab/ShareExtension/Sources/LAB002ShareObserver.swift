import Foundation

func observeCurrentShareExecutable() throws -> LAB002LocalRoleObservation {
    try LAB002LiveMachOObserver.observe(
        fixedBundle: .main,
        compiledAnchor: unsafeBitCast(
            oprobe_share_anchor as @convention(c) () -> Void,
            to: UnsafeRawPointer.self
        ),
        fixedRole: .shareExtension
    )
}
