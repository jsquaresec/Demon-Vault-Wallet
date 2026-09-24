# Phase 2 Desktop Platform Baseline

## Windows

The Tauri shell uses the platform WebView runtime. Phase 2 CI verifies Rust/Tauri compilation on the current GitHub-hosted Windows runner. Production installer signing is deferred to release phases.

## macOS

The shell is compiled/checked on the current GitHub-hosted macOS runner. Apple Silicon and Intel remain required production targets; Phase 2 establishes architecture-neutral application code. Production code signing/notarization remains deferred.

## Linux

Tauri 2 requires WebKitGTK 4.1 and supporting development packages. CI installs the documented Debian/Ubuntu prerequisites before checking the workspace. Release builds later must use an intentionally selected baseline distro to control glibc/runtime compatibility.

## Portability rules

- Core crates cannot depend on path separators or OS-specific hard-coded directories.
- OS facilities are introduced behind platform interfaces only when needed.
- No core behavior may assume Windows Registry, macOS Keychain, or Unix permissions directly.
- Cross-platform CI is a mandatory phase gate, not a best-effort check.
