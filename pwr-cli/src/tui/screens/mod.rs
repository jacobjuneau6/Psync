//! Screen implementations for the pwr TUI.

use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

/// Trait implemented by every TUI screen.
pub trait Screen {
    /// Render this screen into the given area.
    fn render(&mut self, f: &mut Frame, area: Rect);

    /// Handle a keyboard input event.
    /// Return true if the event was consumed.
    fn handle_input(&mut self, key: KeyEvent) -> bool;
}

pub mod project_list;
pub mod project_creator;
pub mod log_viewer;
pub mod operation;

pub use project_list::ProjectListScreen;
pub use project_creator::ProjectCreatorScreen;
pub use log_viewer::LogViewerScreen;
pub use operation::OperationOverlay;
