import UIKit

final class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        oprobe_share_anchor()
        let observationResult: Result<Void, Error> = Result {
            try observeCurrentShareExecutable()
        }

        view.backgroundColor = .systemBackground

        let titleLabel = UILabel()
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = .preferredFont(forTextStyle: .title2)
        titleLabel.text = "DemoLab Share Extension"
        titleLabel.textAlignment = .center

        let detailLabel = UILabel()
        detailLabel.translatesAutoresizingMaskIntoConstraints = false
        detailLabel.font = .preferredFont(forTextStyle: .body)
        switch observationResult {
        case .success:
            detailLabel.text =
                "The fixed LAB-002 share-extension report was published."
        case .failure:
            detailLabel.text =
                "No valid collecting LAB-002 session was available."
        }
        detailLabel.textAlignment = .center
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 0

        let doneButton = UIButton(type: .system)
        doneButton.translatesAutoresizingMaskIntoConstraints = false
        doneButton.setTitle("Done", for: .normal)
        doneButton.addTarget(self, action: #selector(finish), for: .touchUpInside)

        let stack = UIStackView(arrangedSubviews: [titleLabel, detailLabel, doneButton])
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 16

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    @objc private func finish() {
        extensionContext?.completeRequest(returningItems: nil)
    }
}
