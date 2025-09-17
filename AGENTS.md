# Repository Guidelines

## Project Structure & Module Organization
Core Rust sources live in `src/` (`auth.rs`, `dcom.rs`, `rpc.rs`, `wmi.rs`, `lib.rs`). Integration and scenario tests are under `tests/`, while runnable demos sit in `examples/` (`test_connect.rs`). Public FFI surface definitions stay in `include/linux_wmi.h`, and `wmi_shim.cs` offers the .NET binding. Build output lands in `target/`; keep it out of version control. Reference material and specs are stored in `docs/`.

## Build, Test, and Development Commands
- `cargo build` — compile the `linux_wmi` cdylib locally (outputs to `target/debug`).
- `cargo build --release` — produce optimized artifacts for packaging.
- `cargo build --target x86_64-unknown-linux-gnu` — emit an x64 Linux build (install the Rust target first via `rustup target add x86_64-unknown-linux-gnu`).
- `cargo build --target aarch64-unknown-linux-gnu --release` — produce the ARM64 Linux artifact; requires the cross target (`rustup target add aarch64-unknown-linux-gnu`).
- `cargo test` — run all unit and integration tests under `src/` and `tests/`.
- `cargo run --example test_connect` — execute the connectivity sample against a WMI endpoint.
- `cargo fmt` / `cargo clippy --all-targets` — auto-format and lint the Rust sources.

## Coding Style & Naming Conventions
Use Rust 2021 idioms, four-space indentation, and `snake_case` for modules/functions, `CamelCase` for types, and `SCREAMING_SNAKE_CASE` constants. Always run `cargo fmt` before committing; address `cargo clippy` warnings unless you have a documented exception. Keep unsafe blocks minimal and annotated. When editing `wmi_shim.cs`, follow standard .NET naming (PascalCase for public members) and ensure signatures match the C header.

## Testing Guidelines
Prefer focused unit tests alongside the Rust modules; place cross-component flows in `tests/`. Name tests descriptively (`test_connect_fails_without_credentials`). When changes impact the FFI, extend the integration coverage and, where possible, exercise the relevant example. Aim for deterministic tests—avoid external network dependencies without guards.

## Commit & Pull Request Guidelines
Write imperative, present-tense commit subjects (`Add credential fallback`) and include a short body when context is needed. Keep commits scoped to one concern (code, docs, or build) and ensure each builds and tests cleanly. Pull requests should summarize the change, list manual/automated verification, and link issue IDs where applicable. Include screenshots or logs when altering observable behavior or tooling output.

## Interop & Security Notes
Regenerate bindings whenever editing `include/linux_wmi.h` or the C# shim to prevent ABI drift. Never commit real credentials or endpoint details; use `.env` examples instead. Review any added cryptography or authentication changes with a second maintainer before merge.
