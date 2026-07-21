import DemoFramework
import SwiftUI

@main
struct DemoLabApp: App {
    var body: some Scene {
        WindowGroup {
            DemoLabView()
        }
    }
}

private struct DemoLabView: View {
    private let frameworkMessage = DLDemoMessage.fixedString()

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 52))
                .foregroundStyle(.green)

            Text("DemoLab")
                .font(.largeTitle.bold())

            Text(frameworkMessage)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Text("First-party build fixture")
                .font(.caption.monospaced())
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.green.opacity(0.12), in: Capsule())
        }
        .padding(24)
    }
}
