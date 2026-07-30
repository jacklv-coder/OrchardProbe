import Foundation

func observeCurrentMainExecutable() throws -> LAB002LocalRoleObservation {
    try LAB002LiveMachOObserver.observe(
        fixedBundle: .main,
        compiledAnchor: unsafeBitCast(
            oprobe_main_anchor as @convention(c) () -> Void,
            to: UnsafeRawPointer.self
        ),
        fixedRole: .mainApp
    )
}
