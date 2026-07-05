use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

use crate::config;
use crate::error::Result;

/// Types of operations that can be logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Archive,
    Restore,
}

/// Status of a logged transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    Started,
    Completed,
    Failed,
}

/// A single transaction entry in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction ID.
    pub id: Uuid,

    /// When the transaction was recorded.
    pub timestamp: DateTime<Utc>,

    /// What operation was performed.
    pub operation: Operation,

    /// Project UUID (from .project.toml).
    pub project_uuid: Uuid,

    /// Project name.
    pub project_name: String,

    /// Local path.
    pub local_path: String,

    /// Remote path.
    pub remote_path: String,

    /// Size in bytes transferred.
    pub size_bytes: u64,

    /// Current status.
    pub status: TransactionStatus,

    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
}

impl Transaction {
    /// Create a new "started" transaction.
    pub fn started(
        operation: Operation,
        project_uuid: Uuid,
        project_name: &str,
        local_path: &str,
        remote_path: &str,
        size_bytes: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            operation,
            project_uuid,
            project_name: project_name.to_string(),
            local_path: local_path.to_string(),
            remote_path: remote_path.to_string(),
            size_bytes,
            status: TransactionStatus::Started,
            error: None,
            duration_secs: None,
        }
    }

    /// Mark as completed with timing.
    pub fn completed(&mut self, start: DateTime<Utc>) {
        self.status = TransactionStatus::Completed;
        self.duration_secs =
            Some((Utc::now() - start).num_milliseconds() as f64 / 1000.0);
    }

    /// Mark as failed with an error.
    pub fn failed(&mut self, error: &str, start: DateTime<Utc>) {
        self.status = TransactionStatus::Failed;
        self.error = Some(error.to_string());
        self.duration_secs =
            Some((Utc::now() - start).num_milliseconds() as f64 / 1000.0);
    }
}

/// Path to the transaction log file.
pub fn log_path() -> PathBuf {
    config::transaction_log_path()
}

/// Append a transaction entry to the log file (JSONL format).
pub fn append_transaction(transaction: &Transaction) -> Result<()> {
    let dir = log_path().parent().unwrap().to_path_buf();
    fs::create_dir_all(&dir)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())?;

    let line = serde_json::to_string(transaction)?;
    writeln!(file, "{}", line)?;

    log::info!(
        "Transaction {} logged: {} of '{}' ({})",
        transaction.id,
        serde_json::to_string(&transaction.operation).unwrap_or_default(),
        transaction.project_name,
        serde_json::to_string(&transaction.status).unwrap_or_default(),
    );

    Ok(())
}

/// Read all transactions from the log file.
pub fn read_transactions() -> Result<Vec<Transaction>> {
    let path = log_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&path)?;
    let mut transactions = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Transaction>(line) {
            Ok(tx) => transactions.push(tx),
            Err(e) => {
                log::warn!("Skipping malformed transaction line: {}", e);
            }
        }
    }

    Ok(transactions)
}

/// Find any incomplete (Started) transactions — these represent interrupted
/// operations that may need recovery.
pub fn find_incomplete_transactions() -> Result<Vec<Transaction>> {
    let all = read_transactions()?;
    Ok(all
        .into_iter()
        .filter(|tx| tx.status == TransactionStatus::Started)
        .collect())
}

/// Get recent transactions for a project.
pub fn recent_for_project(project_uuid: &Uuid, limit: usize) -> Result<Vec<Transaction>> {
    let all = read_transactions()?;
    let mut matching: Vec<_> = all
        .into_iter()
        .filter(|tx| tx.project_uuid == *project_uuid)
        .collect();
    matching.reverse();
    matching.truncate(limit);
    Ok(matching)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::started(
            Operation::Archive,
            Uuid::new_v4(),
            "testproj",
            "/home/jacob/Projects/testproj",
            "nas:/srv/projects/testproj",
            1_000_000,
        );
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.project_name, "testproj");
        assert_eq!(decoded.status, TransactionStatus::Started);
        assert_eq!(decoded.operation, Operation::Archive);
    }
}
