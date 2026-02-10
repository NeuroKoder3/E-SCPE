//! Structured error types for the E-SCPE library.
//!
//! Every public library function returns [`Result<T>`] which carries a
//! domain-specific [`EscpeError`].  The FFI boundary converts these into
//! integer status codes via [`FfiErrorCode`].

use thiserror::Error;

// ---------------------------------------------------------------------------
// Primary error enum
// ---------------------------------------------------------------------------

/// Domain-specific error type for the E-SCPE library.
#[derive(Error, Debug)]
pub enum EscpeError {
    #[error("CHSH: {0}")]
    Chsh(String),

    #[error("ledger: {0}")]
    Ledger(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("license: {0}")]
    License(String),

    #[error("report: {0}")]
    Report(String),

    #[error("tag: {0}")]
    Tag(String),

    #[error("config: {0}")]
    Config(String),

    #[error("validation: {0}")]
    Validation(String),

    /// Direct database errors (auto-converted via `?` in the ledger module).
    #[error("database: {0}")]
    Database(#[from] rusqlite::Error),

    /// Catch-all for errors that do not fit a specific domain.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the library.
pub type Result<T> = std::result::Result<T, EscpeError>;

// ---------------------------------------------------------------------------
// FFI error codes
// ---------------------------------------------------------------------------

/// Integer status codes returned across the C-ABI boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiErrorCode {
    Ok = 0,
    InvalidArgument = -1,
    LedgerError = -2,
    SigningError = -3,
    LicenseError = -4,
    ChshError = -5,
    TagError = -6,
    IoError = -7,
    DatabaseError = -8,
    ConfigError = -9,
    ReportError = -10,
    InternalError = -99,
}

impl From<&EscpeError> for FfiErrorCode {
    fn from(e: &EscpeError) -> Self {
        match e {
            EscpeError::Chsh(_) => Self::ChshError,
            EscpeError::Ledger(_) => Self::LedgerError,
            EscpeError::Signing(_) => Self::SigningError,
            EscpeError::License(_) => Self::LicenseError,
            EscpeError::Report(_) => Self::ReportError,
            EscpeError::Tag(_) => Self::TagError,
            EscpeError::Config(_) => Self::ConfigError,
            EscpeError::Validation(_) => Self::InvalidArgument,
            EscpeError::Database(_) => Self::DatabaseError,
            EscpeError::Other(_) => Self::InternalError,
        }
    }
}

// ---------------------------------------------------------------------------
// Context extension trait
// ---------------------------------------------------------------------------

/// Extension trait that adds domain-specific context to any `Result<T, E>`.
///
/// Usage mirrors `anyhow::Context` but tags the error with the originating
/// subsystem so that callers (and the FFI boundary) can categorise failures.
///
/// ```ignore
/// std::fs::read(path).ctx_ledger("read ledger file")?;
/// ```
pub trait ResultExt<T> {
    fn ctx_chsh(self, msg: &str) -> Result<T>;
    fn ctx_ledger(self, msg: &str) -> Result<T>;
    fn ctx_signing(self, msg: &str) -> Result<T>;
    fn ctx_license(self, msg: &str) -> Result<T>;
    fn ctx_report(self, msg: &str) -> Result<T>;
    fn ctx_tag(self, msg: &str) -> Result<T>;
    fn ctx_config(self, msg: &str) -> Result<T>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for std::result::Result<T, E> {
    fn ctx_chsh(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Chsh(format!("{msg}: {e}")))
    }
    fn ctx_ledger(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Ledger(format!("{msg}: {e}")))
    }
    fn ctx_signing(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Signing(format!("{msg}: {e}")))
    }
    fn ctx_license(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::License(format!("{msg}: {e}")))
    }
    fn ctx_report(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Report(format!("{msg}: {e}")))
    }
    fn ctx_tag(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Tag(format!("{msg}: {e}")))
    }
    fn ctx_config(self, msg: &str) -> Result<T> {
        self.map_err(|e| EscpeError::Config(format!("{msg}: {e}")))
    }
}

/// Same as [`ResultExt`] but for `Option<T>` (converts `None` into an error).
pub trait OptionExt<T> {
    fn required_chsh(self, msg: &str) -> Result<T>;
    fn required_ledger(self, msg: &str) -> Result<T>;
    fn required_signing(self, msg: &str) -> Result<T>;
    fn required_license(self, msg: &str) -> Result<T>;
    fn required_config(self, msg: &str) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn required_chsh(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| EscpeError::Chsh(msg.to_string()))
    }
    fn required_ledger(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| EscpeError::Ledger(msg.to_string()))
    }
    fn required_signing(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| EscpeError::Signing(msg.to_string()))
    }
    fn required_license(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| EscpeError::License(msg.to_string()))
    }
    fn required_config(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| EscpeError::Config(msg.to_string()))
    }
}
