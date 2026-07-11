use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use super::Screen;

/// Interactive form for creating .project.toml files.
pub struct ProjectCreatorScreen {
    /// Currently focused field index (0 = name, 1 = local path)
    focus: usize,
    name: String,
    local_path: String,
    status_message: String,
}

impl ProjectCreatorScreen {
    pub fn new() -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let name = std::env::current_dir()
            .ok()
            .and_then(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().to_string())
            })
            .unwrap_or_default();

        Self {
            focus: 0,
            name,
            local_path: cwd,
            status_message: String::new(),
        }
    }
}

impl Screen for ProjectCreatorScreen {
    fn render(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Name field
                Constraint::Length(3), // Path field
                Constraint::Length(1), // Status
                Constraint::Min(1),    // Help
            ])
            .split(area);

        // Name field
        let name_style = if self.focus == 0 {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        let name_block = Block::default()
            .title("Project Name")
            .borders(Borders::ALL)
            .style(name_style);
        let name_text = Paragraph::new(self.name.as_str()).block(name_block);
        f.render_widget(name_text, chunks[0]);

        // Path field
        let path_style = if self.focus == 1 {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        let path_block = Block::default()
            .title("Local Path")
            .borders(Borders::ALL)
            .style(path_style);
        let path_text = Paragraph::new(self.local_path.as_str()).block(path_block);
        f.render_widget(path_text, chunks[1]);

        // Status
        if !self.status_message.is_empty() {
            let status = Paragraph::new(Span::styled(
                &self.status_message,
                Style::default().fg(Color::Green),
            ));
            f.render_widget(status, chunks[2]);
        }

        // Help
        let help = Paragraph::new(Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" switch field  "),
            Span::styled("Ctrl+S", Style::default().fg(Color::Yellow)),
            Span::raw(" save  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" cancel"),
        ]));
        f.render_widget(help, chunks[3]);
    }

    fn handle_input(&mut self, key: KeyEvent) -> bool {
        // Ctrl+S must be checked BEFORE the generic Char(c) arm, otherwise
        // Char(c) greedily matches 's' (with or without modifiers) and the
        // save handler is never reached.
        if key.code == KeyCode::Char('s')
            && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
        {
            let path = std::path::PathBuf::from(&self.local_path);
            if !path.is_dir() {
                self.status_message = format!("Error: '{}' is not a directory", self.local_path);
            } else if self.name.is_empty() {
                self.status_message = "Error: name cannot be empty".into();
            } else {
                let remote = format!("server:9742:/srv/pwr/projects/{}", self.name);
                let meta = pwr_core::metadata::ProjectMeta::new_local(
                    self.name.clone(),
                    self.local_path.clone(),
                    remote,
                );
                match pwr_core::project::write_project_file(&path, &meta) {
                    Ok(()) => {
                        self.status_message = format!(
                            "Created .project.toml for '{}'",
                            self.name
                        );
                    }
                    Err(e) => {
                        self.status_message = format!("Error: {}", e);
                    }
                }
            }
            return true;
        }

        match key.code {
            KeyCode::Tab => {
                self.focus = (self.focus + 1) % 2;
                true
            }
            KeyCode::BackTab => {
                self.focus = if self.focus == 0 { 1 } else { 0 };
                true
            }
            KeyCode::Char(c) => {
                match self.focus {
                    0 => self.name.push(c),
                    1 => self.local_path.push(c),
                    _ => {}
                }
                self.status_message.clear();
                true
            }
            KeyCode::Backspace => {
                match self.focus {
                    0 => { self.name.pop(); }
                    1 => { self.local_path.pop(); }
                    _ => {}
                }
                true
            }
            _ => false,
        }
    }
}
