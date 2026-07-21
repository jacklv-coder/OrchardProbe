# Getting started with the Rust workspace

OrchardProbe is pre-alpha. The current workspace provides host-side foundations and a device-free demo only; it has no device backend and cannot decrypt an app or export an IPA.

## Prerequisites

Install Rust through [rustup](https://rustup.rs/) and use the repository's pinned Rust 1.85.0 toolchain. The following commands match CI:

```sh
rustup toolchain install 1.85.0 --profile minimal --component rustfmt --component clippy
```

The repository's `rust-toolchain.toml` selects that toolchain while commands run inside this checkout; it does not require changing your global rustup default.

On macOS, if `cargo` or `rustup` is not found after installing rustup, load rustup's environment into the current shell:

```sh
source "$HOME/.cargo/env"
```

If rustup was installed as Homebrew's keg-only formula instead, add that formula to the current shell's PATH:

```sh
export PATH="$(brew --prefix rustup)/bin:$PATH"
```

To make that PATH setup available in later zsh sessions, follow the instructions printed by rustup or add the equivalent initialization to your shell profile. Confirm the selected tools before continuing:

```sh
rustc --version
cargo --version
```

## Verify the workspace

From the repository root, run the same checks used by pull requests:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -p orchardprobe-cli -- demo --json
```

The final command runs a deterministic, device-free demo and prints its structured result as JSON. It does not contact a device or create an IPA.

To inspect bounded metadata from one local Mach-O file, run:

```sh
cargo run --locked -p orchardprobe-cli -- inspect path/to/Mach-O --json
```

`inspect` accepts one regular file. It rejects directories and symbolic links, does not recurse through an app bundle, and does not unpack an IPA. Its encryption result is Mach-O header metadata only: a missing encryption command or `cryptid == 0` is never reported as proof of plaintext. See [the inspect contract](macho-inspect.md) for supported formats, limits, and JSON fields.

`--locked` makes Cargo use the committed `Cargo.lock` exactly. If dependency metadata changes intentionally, regenerate the lockfile in the same change and then rerun all four commands without removing `--locked`.

The workspace tests also compile the checked-in Draft 2020-12 schemas, validate all golden and negative fixtures, and round-trip each golden through its Rust wire type. See the [versioned contract guide](schemas.md) for versions, limits, and evidence semantics.

## Architecture boundary

Host parsing and orchestration live in Rust. A future Objective-C/C device helper will be deliberately narrow and capability-scoped. See [ADR-0001](../architecture/ADR-0001-rust-host.md) for the trust boundary and the requirements that must be met before a device backend is added.
