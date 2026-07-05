use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use super::Screen;

/// Scrollable viewer for the transaction log.
pub struct LogViewerScreen {
    table_state: TableState,
    entries: Vec<LogEntry>,
}

struct LogEntry {
    timestamp: String,
    operation: String,
    project: String,
    size: String,
    status: String,
}

impl LogViewerScreen {
    pub fn new() -> Self {
        let entries = Self::load_log();
        Self {
            table_state: TableState::default(),
            entries,
        }
    }

    fn load_log() -> Vec<LogEntry> {
        match pwr_core::transaction::read_transactions() {
            Ok(transactions) => transactions
                .into_iter()
                .map(|tx| {
                    let status = match tx.status {
                        pwr_core::transaction::TransactionStatus::Completed => "OK",
                        pwr_core::transaction::TransactionStatus::Failed => "FAILED",
                        pwr_core::transaction::TransactionStatus::Started => "...",
                    };
                    LogEntry {
                        timestamp: tx.timestamp.format("%Y-%m-%d %H:%M").to_string(),
                        operation: format!("{:?}", tx.operation).to_lowercase(),
                        project: tx.project_name,
                        size: pwr_core::metadata::human_size(tx.size_bytes),
                        status: status.to_string(),
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Screen for LogViewerScreen {
    fn render(&mut self, f: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from("Time"),
            Cell::from("Op"),
            Cell::from("Project"),
            Cell::from("Size"),
            Cell::from("Status"),
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let rows: Vec<Row> = self
            .entries
            .iter()
            .map(|e| {
                let status_style = match e.status.as_str() {
                    "OK" => Style::default().fg(Color::Green),
                    "FAILED" => Style::default().fg(Color::Red),
                    _ => Style::default().fg(Color::Yellow),
                };
                Row::new(vec![
                    Cell::from(e.timestamp.clone()),
                    Cell::from(e.operation.clone()),
                    Cell::from(e.project.clone()),
                    Cell::from(e.size.clone()),
                    Cell::from(Span::styled(&e.status, status_style)),
                ])
            })
            .collect();

        let table = Table::new(rows, [
            Constraint::Length(17),
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(10),
        ])
        .header(header)
        .block(
            Block::default()
                .title("Transaction Log")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn handle_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let i = self.table_state.selected().unwrap_or(0);
                if i > 0 {
                    self.table_state.select(Some(i - 1));
                }
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = self.table_state.selected().unwrap_or(0);
                if i + 1 < self.entries.len() {
                    self.table_state.select(Some(i + 1));
                }
                true
            }
            KeyCode::Char('r') => {
                self.entries = Self::load_log();
                true
            }
            _ => false,
        }
    }
}
