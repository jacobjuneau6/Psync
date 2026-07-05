//! Operation progress overlay displayed during archive and restore transfers.
//!
//! Renders a modal overlay with a progress bar, transfer statistics,
//! and a cancel prompt. The overlay is rendered on top of the active
//! screen and auto-dismisses when the operation completes.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use super::Screen;

/// State for an in-progress archive or restore operation.
pub struct OperationOverlay {
    /// "Archive" or "Restore" for display.
    pub operation_name: String,
    /// Human-readable project name.
    pub project_name: String,
    /// Bytes transferred so far.
    pub bytes_done: u64,
    /// Total bytes to transfer.
    pub bytes_total: u64,
    /// Whether the operation has completed.
    pub completed: bool,
    /// Error message if the operation failed.
    pub error: Option<String>,
    /// Whether the user has requested cancellation.
    pub cancelled: bool,
}

impl OperationOverlay {
    pub fn new_archive(name: &str, total: u64) -> Self {
        Self {
            operation_name: "Archive".into(),
            project_name: name.into(),
            bytes_done: 0,
            bytes_total: total,
            completed: false,
            error: None,
            cancelled: false,
        }
    }

    pub fn new_restore(name: &str, total: u64) -> Self {
        Self {
            operation_name: "Restore".into(),
            project_name: name.into(),
            bytes_done: 0,
            bytes_total: total,
            completed: false,
            error: None,
            cancelled: false,
        }
    }

    /// Update the progress from a transfer callback.
    pub fn update_progress(&mut self, bytes: u64, _total: u64) {
        self.bytes_done = bytes;
    }

    fn progress_fraction(&self) -> f64 {
        if self.bytes_total == 0 {
            return 1.0;
        }
        (self.bytes_done as f64 / self.bytes_total as f64).min(1.0)
    }

    fn speed_mbps(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs < 0.1 {
            return 0.0;
        }
        (self.bytes_done as f64 / (1024.0 * 1024.0)) / elapsed_secs
    }

    fn format_size(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }
}

impl Screen for OperationOverlay {
    fn render(&mut self, f: &mut Frame, area: Rect) {
        // Center the overlay in a 60x8 box
        let overlay_width = 60u16.min(area.width);
        let overlay_height = 8u16.min(area.height);
        let x = (area.width.saturating_sub(overlay_width)) / 2;
        let y = (area.height.saturating_sub(overlay_height)) / 2;

        let overlay_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width: overlay_width,
            height: overlay_height,
        };

        let block = Block::default()
            .title(format!(" {}: {} ", self.operation_name, self.project_name))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));

        let inner = block.inner(overlay_area);
        f.render_widget(block, overlay_area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Progress gauge
                Constraint::Length(1), // Stats line
                Constraint::Length(1), // Cancel hint
            ])
            .split(inner);

        // Progress gauge
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .ratio(self.progress_fraction());
        f.render_widget(gauge, chunks[0]);

        // Stats: bytes done / total, percentage
        let pct = self.progress_fraction() * 100.0;
        let stats = format!(
            "{} / {}  ({:.0}%)",
            Self::format_size(self.bytes_done),
            Self::format_size(self.bytes_total),
            pct,
        );

        let stats_style = if self.completed {
            Style::default().fg(Color::Green)
        } else if self.error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(stats, stats_style))),
            chunks[1],
        );

        // Status message
        let status = if self.completed {
            "Transfer complete — press any key to dismiss".to_string()
        } else if let Some(ref err) = self.error {
            format!("Error: {}", err)
        } else if self.cancelled {
            "Cancelling...".to_string()
        } else {
            "Press Esc to cancel".to_string()
        };

        let status_style = if self.error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(status, status_style))),
            chunks[2],
        );
    }

    fn handle_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.cancelled = true;
                true
            }
            KeyCode::Enter if self.completed || self.error.is_some() => {
                // Signal dismissal handled by caller
                true
            }
            _ => false,
        }
    }
}
