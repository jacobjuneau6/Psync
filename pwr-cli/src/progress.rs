//! Progress reporting for CLI operations.
//!
//! Provides an indicatif-based progress bar for archive and restore
//! operations, plus a simple line-based fallback for non-interactive
//! terminals.

use indicatif::{ProgressBar, ProgressStyle};
use pwr_core::archive::ArchiveStage;

/// Mode for progress display.
pub enum ProgressMode {
    /// Full progress bar with spinner, bar, bytes, and ETA.
    Bar(ProgressBar),
    /// Simple line-by-line output for non-TTY or quiet mode.
    Line,
}

/// Create a progress bar for an archive operation.
pub fn archive_progress_bar(size_bytes: u64) -> ProgressBar {
    let pb = ProgressBar::new(size_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Archiving [{bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// Create a progress bar for a restore operation.
pub fn restore_progress_bar(size_bytes: u64) -> ProgressBar {
    let pb = ProgressBar::new(size_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Restoring [{bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// Update a progress bar based on the archive stage and progress fraction.
pub fn update_archive_progress(pb: &ProgressBar, stage: ArchiveStage, progress: f64) {
    match stage {
        ArchiveStage::Scanning => pb.set_message("Scanning files..."),
        ArchiveStage::Tarring => pb.set_message("Building archive..."),
        ArchiveStage::Compressing => pb.set_message("Compressing..."),
        ArchiveStage::Encrypting => pb.set_message("Encrypting..."),
        ArchiveStage::Hashing => pb.set_message("Verifying..."),
        _ => {}
    }
    pb.set_position((pb.length().unwrap_or(1) as f64 * progress) as u64);
}

/// Print a simple progress line for non-interactive mode.
pub fn print_stage(stage: ArchiveStage) {
    let msg = match stage {
        ArchiveStage::Scanning => "Scanning files...",
        ArchiveStage::Tarring => "Building archive...",
        ArchiveStage::Compressing => "Compressing...",
        ArchiveStage::Encrypting => "Encrypting...",
        ArchiveStage::Hashing => "Computing hash...",
        ArchiveStage::Decrypting => "Decrypting...",
        ArchiveStage::Decompressing => "Decompressing...",
        ArchiveStage::Extracting => "Extracting files...",
    };
    eprintln!("  {}", msg);
}
