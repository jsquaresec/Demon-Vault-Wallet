# Cross-Platform Architecture

Demon Vault targets currently maintained mainstream Windows, macOS, and Linux desktop environments.

## Required release targets
- Windows x86-64.
- macOS Apple Silicon (ARM64).
- macOS Intel (x86-64) while the dependency/toolchain stack remains supportable.
- Linux x86-64 across mainstream distributions through portable packaging plus native packages where practical.

## Platform abstraction
Core wallet logic is portable Rust. OS-specific behavior is isolated behind platform interfaces for filesystem locations/permissions, secure OS facilities, notifications, process behavior, packaging, signing, and update integration.

## Packaging direction
Windows: signed installer. macOS: signed and notarized app bundle and disk image/package. Linux: AppImage or equivalent portable artifact plus `.deb`; `.rpm` may be added after validation.

## CI requirement
Before production, CI must compile and test supported targets and release candidates must be exercised on real Windows, macOS, and Linux environments. Cross-platform support means supported mainstream systems, not every historical OS release or unusual distribution.
