//! Integration-test placeholder.
//!
//! `stryke-email` is a `cdylib`-only crate (no `rlib`), so an integration test
//! cannot link its `extern "C"` exports. The real coverage is:
//!
//!   * `src/lib.rs` `#[cfg(test)] mod tests` — unit tests for the pure logic
//!     (template merge, address validation/parsing, List-Unsubscribe value,
//!     default ports by TLS mode, HTML multipart build). These run on
//!     `cargo test`.
//!   * `t/test_stryke_email_surface.stk` — pins every `Email::*` wrapper and
//!     the connection-free helpers, with no SMTP server.
//!   * `t/test_email.stk` — single send + a personalized campaign against a
//!     live SMTP server (`$SMTP_HOST`), short-circuited when none is set.

#[test]
fn cdylib_crate_compiles() {
    // Reaching here means every `extern "C"` `email__*` export type-checked and
    // linked into the test harness — the minimum contract for a cdylib crate.
}
