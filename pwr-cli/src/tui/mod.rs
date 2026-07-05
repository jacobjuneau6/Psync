//! Terminal UI for pwr — interactive project management.
//!
//! Provides screens for browsing projects, creating .project.toml files,
//! and monitoring archive/restore operations. Built with ratatui and
//! crossterm.

mod screens;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame, Terminal,
};
use std::io;

use screens::Screen;

/// Application state shared across all screens.
pub struct App {
    /// Currently active screen.
    pub current_screen: Box<dyn Screen>,
    /// Tab labels for the top navigation bar.
    pub tabs: Vec<String>,
    /// Index of the active tab.
    pub active_tab: usize,
    /// Set to true to exit the TUI.
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        let tabs = vec![
            "Projects".to_string(),
            "Create".to_string(),
            "Log".to_string(),
        ];

        Self {
            current_screen: Box::new(screens::ProjectListScreen::new()),
            tabs,
            active_tab: 0,
            should_quit: false,
        }
    }

    /// Switch to a different screen by tab index.
    pub fn switch_tab(&mut self, index: usize) {
        self.active_tab = index;
        self.current_screen = match index {
            0 => Box::new(screens::ProjectListScreen::new()),
            1 => Box::new(screens::ProjectCreatorScreen::new()),
            2 => Box::new(screens::LogViewerScreen::new()),
            _ => return,
        };
    }
}

/// Run the TUI application. Blocks until the user quits.
pub fn run() -> Result<(), String> {
    // Terminal setup
    enable_raw_mode().map_err(|e| format!("raw mode: {}", e))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| format!("alt screen: {}", e))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|e| format!("terminal: {}", e))?;

    let mut app = App::new();

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app);

    // Cleanup
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn run_event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), String> {
    loop {
        // Draw current screen
        terminal
            .draw(|f| render_frame(f, app))
            .map_err(|e| format!("draw: {}", e))?;

        // Handle input
        if let Event::Key(key) = event::read().map_err(|e| format!("input: {}", e))? {
            if key.kind == KeyEventKind::Release {
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.should_quit = true;
                }
                KeyCode::Char('1') => app.switch_tab(0),
                KeyCode::Char('2') => app.switch_tab(1),
                KeyCode::Char('3') => app.switch_tab(2),
                KeyCode::Tab => {
                    let next = (app.active_tab + 1) % app.tabs.len();
                    app.switch_tab(next);
                }
                _ => {
                    app.current_screen.handle_input(key);
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Render the full application frame: tabs at top, active screen in center,
/// status bar at bottom.
fn render_frame(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Tab bar
            Constraint::Min(1),    // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    // Tab bar
    let tabs: Vec<Line> = app
        .tabs
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == app.active_tab {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(format!(" {} ({}) ", name, i + 1), style))
        })
        .collect();

    let tabs_widget = Tabs::new(tabs)
        .block(Block::default().borders(Borders::BOTTOM))
        .select(app.active_tab);
    f.render_widget(tabs_widget, chunks[0]);

    // Main content
    app.current_screen.render(f, chunks[1]);

    // Status bar
    let status = Paragraph::new(Line::from(Span::styled(
        " q quit | Tab switch | 1-3 tabs | ? help ",
        Style::default().fg(Color::DarkGray),
    )))
    .block(Block::default());
    f.render_widget(status, chunks[2]);
}
