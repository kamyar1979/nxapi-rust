//! Optional persistence contract for device authentication sessions.

use async_trait::async_trait;
use std::{error::Error, fmt, time::SystemTime};

/// Storage failure. Implementations must not include cookies or credentials in errors.
pub type SessionStoreError = Box<dyn Error + Send + Sync>;

/// A sensitive NX-API cookie and the device's next refresh deadline.
///
/// The deadline uses wall-clock time so a different process can restore it.
/// Stores should protect this value as a credential and may expire it after
/// `refresh_at`; NX-API will authenticate again when no session is available.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredSession {
    /// The complete HTTP Cookie header value, such as `APIC-cookie=...`.
    pub cookie: String,
    /// When the device session should next be refreshed.
    pub refresh_at: SystemTime,
}

impl fmt::Debug for StoredSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSession")
            .field("cookie", &"<redacted>")
            .field("refresh_at", &self.refresh_at)
            .finish()
    }
}

/// Backend-independent persistence for a device authentication session.
///
/// A key must identify both the device endpoint and login identity. A store
/// implementation must keep cookie values confidential. This contract does not
/// coordinate concurrent logins across processes; implementations that need
/// that guarantee must provide separate distributed coordination.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Load the most recently saved session, if one exists.
    async fn load(&self, key: &str) -> Result<Option<StoredSession>, SessionStoreError>;

    /// Save or replace a session after successful login or refresh.
    async fn save(&self, key: &str, session: &StoredSession) -> Result<(), SessionStoreError>;

    /// Remove a session rejected by the device.
    async fn delete(&self, key: &str) -> Result<(), SessionStoreError>;
}
