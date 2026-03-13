//! Session context — re-exports from bolt-core shared session authority.
//!
//! RC2-EXEC-E (AC-RC-07): Transport-agnostic session primitives now live
//! in `bolt_core::session`. This module re-exports for backward compatibility
//! with existing daemon call-sites.

pub use bolt_core::session::SessionContext;

// Re-export SessionState for daemon consumers.
pub use bolt_core::session::SessionState;
