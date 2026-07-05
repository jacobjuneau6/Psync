pub mod config;
pub mod error;
pub mod metadata;
pub mod project;
pub mod transaction;

// New modules for protocol-based architecture (stubs until later commits)
pub mod protocol;
pub mod frame;
pub mod crypto;
pub mod archive;
pub mod integrity;

pub use config::PwrConfig;
pub use error::{PwrError, Result};
pub use metadata::ProjectMeta;
pub use project::PROJECT_FILE;
