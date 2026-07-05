//! Wire protocol message types shared between client and server.
//! Stub — full message definitions in commit 8.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Information about a project returned in list/status queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub uuid: Uuid,
    pub name: String,
    pub size_bytes: u64,
    pub file_count: u32,
    pub created_at: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
}
