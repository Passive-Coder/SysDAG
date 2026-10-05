//! Full-screen SysDAG app: landing spectacle, then a restrained analysis viewer.

use std::io::{self, stdout, IsTerminal};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

mod app;
#[cfg(target_os = "linux")]
mod browser;
mod draw;
mod landing;
mod motion;
mod theme;

pub use app::Session;
pub use landing::{run_landing, LandingAction};

use app::{App, View};
#[cfg(target_os = "linux")]
use browser::open_graph_in_browser;
use draw::draw;

pub fn should_open(plain: bool, json: bool) -> bool {
    !plain && !json && io::stdout().is_terminal()
}

pub fn run(session: Session) -> Result<i32> {
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    execute!(
        out,
        EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;
    let mut app = App::new(session);
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result?;
    Ok(app.exit_code())
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    let mut last = Instant::now();
    while !app.quit {
        app.poll_analysis();
        let now = Instant::now();
        app.tick(now.saturating_duration_since(last));
        last = now;

        terminal.draw(|f| draw(f, app))?;

        // GitHub TUIKit: animate only while effects run; idle is event-driven.
        let timeout = if app.busy() {
            Duration::from_millis(16)
        } else {
            Duration::from_secs(60)
        };
        if !event::poll(timeout)? {
            continue;
        }
        match event::read()? {
            Event::Key(k) => on_key(app, k),
            Event::Mouse(m) => match m.kind {
                MouseEventKind::ScrollDown => app.scroll = app.scroll.saturating_add(1),
                MouseEventKind::ScrollUp => app.scroll = app.scroll.saturating_sub(1),
                _ => {}
            },
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

fn on_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        KeyCode::Tab => app.set_view(app.view.next()),
        KeyCode::BackTab => {
            let prev = match app.view {
                View::Overview => View::Inspect,
                View::Graph => View::Overview,
                View::Events => View::Graph,
                View::Inspect => View::Events,
            };
            app.set_view(prev);
        }
        KeyCode::Char('f') => {
            app.filter = app.filter.next();
        }
        KeyCode::Char(c) if View::from_digit(c).is_some() => {
            app.set_view(View::from_digit(c).unwrap());
        }
        KeyCode::Char(c) if View::from_letter(c).is_some() => {
            app.set_view(View::from_letter(c).unwrap());
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.view == View::Inspect {
                app.move_cursor(1);
            } else {
                app.scroll = app.scroll.saturating_add(1);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.view == View::Inspect {
                app.move_cursor(-1);
            } else {
                app.scroll = app.scroll.saturating_sub(1);
            }
        }
        KeyCode::PageDown => app.scroll = app.scroll.saturating_add(10),
        KeyCode::PageUp => app.scroll = app.scroll.saturating_sub(10),
        KeyCode::Home => app.scroll = 0,
        KeyCode::Char('[') => app.move_window(-1),
        KeyCode::Char(']') => app.move_window(1),
        #[cfg(target_os = "linux")]
        KeyCode::Char('v') => {
            if let Some(graph) = app.graph().cloned() {
                app.notice = Some(match open_graph_in_browser(&graph) {
                    Ok(path) => (Instant::now(), format!("opened {}", path.display())),
                    Err(err) => (Instant::now(), format!("browser failed: {err:#}")),
                });
            }
        }
        _ => {}
    }
}
