import Foundation

@_silgen_name("oprobe_framework_anchor")
private func oprobe_framework_anchor()

private final class LAB002FrameworkBundleToken {}

private func currentFrameworkObservation()
    throws -> LAB002LocalRoleObservation {
    try LAB002LiveMachOObserver.observe(
        fixedBundle: Bundle(for: LAB002FrameworkBundleToken.self),
        compiledAnchor: unsafeBitCast(
            oprobe_framework_anchor as @convention(c) () -> Void,
            to: UnsafeRawPointer.self
        ),
        fixedRole: .framework
    )
}

public func observeCurrentFrameworkImage() throws {
    let bundle = Bundle(for: LAB002FrameworkBundleToken.self)
    let observation = try currentFrameworkObservation()
    try LAB002RoleReportPublisher.publish(
        observation,
        fixedBundle: bundle,
        fixedRole: .framework
    )
}
