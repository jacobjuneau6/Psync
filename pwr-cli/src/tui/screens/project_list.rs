use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use super::Screen;

/// Browse tracked projects with status, size, and last-sync information.
pub struct ProjectListScreen {
    table_state: TableState,
    projects: Vec<ProjectEntry>,
}

struct ProjectEntry {
    name: String,
    status: String,
    size: String,
    last_sync: String,
}

impl ProjectListScreen {
    pub fn new() -> Self {
        // Load projects from local filesystem
        let projects = Self::load_projects();

        Self {
            table_state: TableState::default().with_selected(0),
            projects,
        }
    }

    fn load_projects() -> Vec<ProjectEntry> {
        // Scan for .project.toml files under the configured root
        let mut entries = Vec::new();
        if let Ok(config) = pwr_core::config::load_config() {
            let root = std::path::PathBuf::from(&config.local_root);
            if let Ok(projects) = pwr_core::project::find_projects(&root) {
                entries = projects
                    .into_iter()
                    .map(|(_, meta)| ProjectEntry {
                        name: meta.name,
                        status: if meta.is_archived() {
                            "archived".into()
                        } else {
                            "local".into()
                        },
                        size: meta.size_human(),
                        last_sync: meta.last_sync.format("%Y-%m-%d").to_string(),
                    })
                    .collect();
            }
        }
        entries
    }
}

impl Screen for ProjectListScreen {
    fn render(&mut self, f: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from("Status"),
            Cell::from("Name"),
            Cell::from("Size"),
            Cell::from("Last Sync"),
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let rows: Vec<Row> = self
            .projects
            .iter()
            .map(|p| {
                let status_style = if p.status == "local" {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                Row::new(vec![
                    Cell::from(Span::styled(&p.status, status_style)),
                    Cell::from(p.name.clone()),
                    Cell::from(p.size.clone()),
                    Cell::from(p.last_sync.clone()),
                ])
            })
            .collect();

        let table = Table::new(rows, [
            Constraint::Length(10),
            Constraint::Length(25),
            Constraint::Length(10),
            Constraint::Length(12),
        ])
        .header(header)
        .block(
            Block::default()
                .title("Projects")
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
                if i + 1 < self.projects.len() {
                    self.table_state.select(Some(i + 1));
                }
                true
            }
            KeyCode::Char('r') => {
                // Refresh project list
                self.projects = Self::load_projects();
                true
            }
            _ => false,
        }
    }
}
