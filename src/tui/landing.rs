//! Full-screen landing: decrypting wordmark, particle rain, TachyonFX spectacle.

use std::io::{self, stdout};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tachyonfx::fx::{self, EvolveSymbolSet, Glitch};
use tachyonfx::pattern::{DissolvePattern, RadialPattern};
use tachyonfx::{
    Duration as FxDuration, Effect, EffectRenderer, Interpolation, IntoEffect, Motion,
};

use super::motion::{self, burst_cells, decrypt, hsl, lerp_color, pad_cells, Spring};
use super::theme::{
    self, bold, fg, BG, BLUE, DIM, GREEN, INK, LAVENDER, MUTED, PEACH, ROSE, SURFACE, TEAL, TEXT,
    YELLOW,
};

const LOGO: &[&str] = &[
    "███████╗██╗   ██╗███████╗██████╗  █████╗  ██████╗",
    "██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝",
    "███████╗ ╚████╔╝ ███████╗██║  ██║███████║██║  ███╗",
    "╚════██║  ╚██╔╝  ╚════██║██║  ██║██╔══██║██║   ██║",
    "███████║   ██║   ███████║██████╔╝██║  ██║╚██████╔╝",
];

const TAGLINE: &str = "process graphs  ·  WL fingerprints  ·  micro-VM tracing";

const RAIN: &[char] = &[
    '0', '1', 'ｱ', 'ﾊ', 'ﾐ', 'ﾋ', 'ｰ', 'ｳ', 'ｼ', 'ﾅ', 'ﾓ', 'ﾆ', 'ｻ', 'ﾜ', 'ﾂ', 'ｵ', 'ﾘ', 'ﾎ', 'ｱ',
    '3', '7', 'A', 'F', '░', '▒', '┊',
];

const STARS: &[char] = &['·', '∙', '˙', '˚', '✶', '✦', '⠂', '⠄', '⠁', ' '];
const MAX_SUGGESTIONS: usize = 6;

#[derive(Debug, Clone)]
pub enum LandingAction {
    Quit,
    Run { path: PathBuf, args: Vec<String> },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Item {
    Run,
    Commands,
    Quit,
}

impl Item {
    const ALL: [Item; 3] = [Item::Run, Item::Commands, Item::Quit];

    fn label(self) -> &'static str {
        match self {
            Item::Run => "run this path",
            Item::Commands => "commands",
            Item::Quit => "quit",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Item::Run => "type a file, then enter",
            Item::Commands => "overlay  ·  also ?",
            Item::Quit => "leave the app",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Item::Run => "↵",
            Item::Commands => "?",
            Item::Quit => "q",
        }
    }

    fn index(self) -> usize {
        match self {
            Item::Run => 0,
            Item::Commands => 1,
            Item::Quit => 2,
        }
    }

    fn from_index(i: usize) -> Self {
        Self::ALL[i % Self::ALL.len()]
    }
}

struct Landing {
    reduced: bool,
    opened: Instant,
    frame_dt: Duration,
    input: String,
    suggestions: Vec<String>,
    selected_suggestion: usize,
    caret: bool,
    blink: Instant,
    item: Item,
    focus: Spring,
    overlay: bool,
    flash: Option<Instant>,
    notice: Option<(Instant, String)>,
    action: Option<LandingAction>,
    intro: Option<Effect>,
    spark: Option<Effect>,
    ambient: Option<Effect>,
    rain_phase: f32,
}

impl Landing {
    fn new() -> Self {
        let reduced = motion::reduced_motion();
        let mut land = Self {
            reduced,
            opened: Instant::now(),
            frame_dt: Duration::from_millis(16),
            input: String::new(),
            suggestions: Vec::new(),
            selected_suggestion: 0,
            caret: true,
            blink: Instant::now(),
            item: Item::Run,
            focus: Spring::new(0.0),
            overlay: false,
            flash: None,
            notice: None,
            action: None,
            intro: None,
            spark: None,
            ambient: None,
            rain_phase: 0.0,
        };
        if !reduced {
            land.intro = Some(intro_effect());
            land.spark = Some(spark_effect());
        }
        land
    }

    fn tick(&mut self, dt: Duration) {
        self.frame_dt = dt;
        let secs = dt.as_secs_f32();
        if self.reduced {
            self.focus.snap(self.item.index() as f32);
            self.caret = true;
            return;
        }
        self.focus.step(secs);
        self.rain_phase = (self.rain_phase + secs * 18.0) % 10_000.0;
        if self.blink.elapsed() > Duration::from_millis(480) {
            self.caret = !self.caret;
            self.blink = Instant::now();
        }
        if let Some(start) = self.flash {
            if start.elapsed() > Duration::from_millis(420) {
                self.flash = None;
            }
        }
        if let Some((start, _)) = &self.notice {
            if start.elapsed() > Duration::from_millis(2400) {
                self.notice = None;
            }
        }
        if let Some(fx) = &self.intro {
            if !fx.running() {
                self.intro = None;
                self.ambient = Some(ambient_effect());
            }
        }
        if let Some(fx) = &self.spark {
            if !fx.running() {
                self.spark = None;
            }
        }
    }

    fn busy(&self) -> bool {
        if self.reduced {
            return false;
        }
        true
    }

    fn select(&mut self, item: Item) {
        self.item = item;
        if self.reduced {
            self.focus.snap(item.index() as f32);
        } else {
            self.focus.set(item.index() as f32);
        }
    }

    fn move_sel(&mut self, delta: i32) {
        let n = Item::ALL.len() as i32;
        let next = (self.item.index() as i32 + delta).rem_euclid(n) as usize;
        self.select(Item::from_index(next));
    }

    fn activate(&mut self) {
        match self.item {
            Item::Run => self.submit_path(),
            Item::Commands => self.overlay = !self.overlay,
            Item::Quit => self.action = Some(LandingAction::Quit),
        }
    }

    fn submit_path(&mut self) {
        match parse_run_line(&self.input) {
            None => {
                self.flash = Some(Instant::now());
                self.notice = Some((Instant::now(), "type a path, then enter".into()));
            }
            Some((path, args)) => {
                if path.exists() {
                    self.action = Some(LandingAction::Run { path, args });
                } else {
                    self.flash = Some(Instant::now());
                    self.notice =
                        Some((Instant::now(), format!("{} does not exist", path.display())));
                }
            }
        }
    }

    fn typing(&self) -> bool {
        !self.input.is_empty()
    }

    fn refresh_suggestions(&mut self) {
        self.suggestions = path_suggestions(&self.input);
        self.selected_suggestion = 0;
    }

    fn complete_suggestion(&mut self) {
        if let Some(path) = self.suggestions.get(self.selected_suggestion).cloned() {
            self.input = path;
            self.refresh_suggestions();
        }
    }

    fn move_suggestion(&mut self, delta: i32) {
        let n = self.suggestions.len() as i32;
        if n > 0 {
            self.selected_suggestion =
                (self.selected_suggestion as i32 + delta).rem_euclid(n) as usize;
        }
    }
}

fn path_suggestions(input: &str) -> Vec<String> {
    if input.is_empty() || input.chars().any(char::is_whitespace) {
        return Vec::new();
    }
    if input == "~" {
        return vec!["~/".into()];
    }

    let (prefix, name_prefix) = input
        .rsplit_once('/')
        .map(|(dir, name)| (format!("{dir}/"), name))
        .unwrap_or_else(|| (String::new(), input));
    let directory = if prefix.is_empty() {
        PathBuf::from(".")
    } else {
        expand_home(Path::new(&prefix))
    };
    let mut matches = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&directory) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if ignored_entry(&name, name_prefix) {
                continue;
            }
            let Some(quality) = match_quality(&name, name_prefix) else {
                continue;
            };
            let is_dir = entry.path().is_dir();
            let suffix = if is_dir { "/" } else { "" };
            matches.push((0_u8, quality, kind_rank(&entry.path(), is_dir), format!("{prefix}{name}{suffix}")));
        }
    }

    // A bare filename can refer to a file under examples/ or tests/, so include
    // nearby project files when the immediate directory has few useful matches.
    if prefix.is_empty() && name_prefix.chars().count() >= 2 {
        let mut queue = VecDeque::from([(PathBuf::from("."), 0_u8)]);
        let mut visited = 0;
        while let Some((dir, depth)) = queue.pop_front() {
            if depth >= 3 || visited >= 1200 {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                visited += 1;
                if visited >= 1200 {
                    break;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if ignored_entry(&name, name_prefix) {
                    continue;
                }
                let path = entry.path();
                if path.is_dir() {
                    queue.push_back((path, depth + 1));
                } else if depth > 0 {
                    if let Some(quality) = match_quality(&name, name_prefix) {
                        let shown = path.strip_prefix(".").unwrap_or(&path).display().to_string();
                        matches.push((1, quality, kind_rank(&path, false), shown));
                    }
                }
            }
        }
    }

    matches.sort_by(|a, b| (a.1, a.2, a.0, a.3.len(), &a.3).cmp(&(b.1, b.2, b.0, b.3.len(), &b.3)));
    matches.into_iter().take(MAX_SUGGESTIONS).map(|(_, _, _, path)| path).collect()
}

fn ignored_entry(name: &str, query: &str) -> bool {
    (name.starts_with('.') && !query.starts_with('.'))
        || (matches!(name, "target" | "node_modules" | ".git" | ".sysdag") && query != name)
}

fn match_quality(name: &str, query: &str) -> Option<u8> {
    if query.is_empty() || name.starts_with(query) {
        return Some(0);
    }
    let name = name.to_lowercase();
    let query = query.to_lowercase();
    if name.starts_with(&query) {
        Some(1)
    } else if name.contains(&query) {
        Some(2)
    } else {
        // A subsequence match gives short inputs such as "wlc" a useful
        // workload.c recommendation.
        let mut chars = name.chars();
        query
            .chars()
            .all(|c| chars.by_ref().any(|candidate| candidate == c))
            .then_some(3)
    }
}

fn kind_rank(path: &Path, is_dir: bool) -> u8 {
    if !is_dir && matches!(path.extension().and_then(|ext| ext.to_str()), Some("c" | "py" | "sh" | "strace")) {
        0
    } else if is_dir {
        1
    } else {
        2
    }
}

fn expand_home(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

pub fn run_landing() -> Result<LandingAction> {
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;
    let mut app = Landing::new();
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    result?;
    Ok(app.action.unwrap_or(LandingAction::Quit))
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut Landing,
) -> Result<()> {
    let mut last = Instant::now();
    while app.action.is_none() {
        let now = Instant::now();
        app.tick(now.saturating_duration_since(last));
        last = now;
        terminal.draw(|f| draw(f, app))?;

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
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

fn on_key(app: &mut Landing, key: KeyEvent) {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    if matches!(key.code, KeyCode::Char('c')) && ctrl {
        app.action = Some(LandingAction::Quit);
        return;
    }
    if app.overlay {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => app.overlay = false,
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Esc => {
            if app.typing() {
                app.input.clear();
                app.refresh_suggestions();
            } else {
                app.action = Some(LandingAction::Quit);
            }
        }
        KeyCode::Char('u') if ctrl => {
            app.input.clear();
            app.refresh_suggestions();
        }
        KeyCode::Enter => {
            if app.typing() {
                let valid_path = parse_run_line(&app.input)
                    .map(|(path, _)| expand_home(&path).exists())
                    .unwrap_or(false);
                if valid_path || app.suggestions.is_empty() {
                    app.submit_path();
                } else {
                    app.complete_suggestion();
                }
            } else {
                app.activate();
            }
        }
        KeyCode::Backspace => {
            app.input.pop();
            app.refresh_suggestions();
        }
        KeyCode::Delete => {
            app.input.pop();
            app.refresh_suggestions();
        }
        KeyCode::Down if !app.suggestions.is_empty() => app.move_suggestion(1),
        KeyCode::Up if !app.suggestions.is_empty() => app.move_suggestion(-1),
        KeyCode::Tab if !app.suggestions.is_empty() => app.complete_suggestion(),
        KeyCode::Down | KeyCode::Tab => app.move_sel(1),
        KeyCode::Up | KeyCode::BackTab => app.move_sel(-1),
        KeyCode::Char('?') => app.overlay = true,
        KeyCode::Char(c) if !app.typing() && matches!(c, 'j') => app.move_sel(1),
        KeyCode::Char(c) if !app.typing() && matches!(c, 'k') => app.move_sel(-1),
        KeyCode::Char(c) if !app.typing() && matches!(c, 'q') => {
            app.action = Some(LandingAction::Quit);
        }
        KeyCode::Char(c) if !ctrl && !c.is_control() => {
            app.input.push(c);
            app.refresh_suggestions();
            app.select(Item::Run);
        }
        _ => {}
    }
}

fn draw(f: &mut Frame, app: &mut Landing) {
    f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());

    let cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(1)])
        .split(f.area());

    let rain_w = rain_width(cols[0].width);
    let body = if rain_w == 0 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20)])
            .split(cols[0])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(rain_w),
                Constraint::Min(24),
                Constraint::Length(rain_w),
            ])
            .split(cols[0])
    };

    if rain_w > 0 {
        draw_rain(f, body[0], app, 0);
        draw_stage(f, body[1], app);
        draw_rain(f, body[2], app, 1);
    } else {
        draw_stage(f, body[0], app);
    }
    draw_footer(f, cols[1], app);

    if app.overlay {
        draw_overlay(f, f.area());
    }

    let dt = FxDuration::from_millis(app.frame_dt.as_millis().min(50) as u32);
    let stage = if rain_w > 0 { body[1] } else { body[0] };
    if let Some(fx) = &mut app.intro {
        if fx.running() {
            f.render_effect(fx, stage, dt);
        }
    }
    if let Some(fx) = &mut app.ambient {
        if fx.running() {
            let logo = logo_band(stage);
            f.render_effect(fx, logo, dt);
        }
    }
    if let Some(fx) = &mut app.spark {
        if fx.running() {
            let band = spark_band(stage);
            f.render_effect(fx, band, dt);
        }
    }
}

fn draw_stage(f: &mut Frame, area: Rect, app: &Landing) {
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);
    let inner = inset(area, 2, 0);
    if inner.width < 8 || inner.height < 6 {
        f.render_widget(
            Paragraph::new(Span::styled(" SYSDAG  q quit", bold(BLUE))),
            inner,
        );
        return;
    }

    let compact = inner.height < 24 || inner.width < 52;
    let logo_h = if compact { 2 } else { LOGO.len() as u16 + 1 };
    let suggestion_space = inner.height.saturating_sub(logo_h + 12);
    let suggestions_h = if !app.typing() || app.input.chars().any(char::is_whitespace) {
        0
    } else if app.suggestions.is_empty() {
        2.min(suggestion_space)
    } else {
        (app.suggestions.len() as u16 + 1).min(suggestion_space)
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(logo_h),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(suggestions_h),
            Constraint::Min(6),
        ])
        .split(inner);

    draw_logo(f, chunks[1], app, compact);
    draw_tagline(f, chunks[2], app);
    draw_sparkline(f, chunks[3], app);
    draw_path(f, chunks[4], app);
    draw_suggestions(f, chunks[5], app);
    draw_menu(f, chunks[6], app);
}

fn draw_logo(f: &mut Frame, area: Rect, app: &Landing, compact: bool) {
    let t = motion::elapsed_frac(app.opened, 920);
    let time = app.opened.elapsed().as_secs_f32();
    if compact {
        let word = if app.reduced {
            pad_cells("SYSDAG", 8)
        } else {
            decrypt("SYSDAG", 8, t)
        };
        let color = if app.reduced {
            BLUE
        } else {
            hsl(208.0 + time.sin() * 18.0, 0.62, 0.66)
        };
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(format!(" {word}"), bold(color))),
                Line::from(Span::styled("  syscall DAG", fg(MUTED))),
            ]),
            area,
        );
        return;
    }

    let width = logo_width();
    let mut lines = Vec::new();
    for (i, row) in LOGO.iter().enumerate() {
        let delay = i as f32 * 0.07;
        let local = if app.reduced {
            1.0
        } else {
            ((t - delay) / 0.55).clamp(0.0, 1.0)
        };
        let text = if app.reduced {
            pad_cells(row, width)
        } else {
            decrypt(row, width, local)
        };
        let mut spans = vec![Span::styled(" ", fg(DIM))];
        for (col, ch) in text.chars().enumerate() {
            let hue = 206.0 + col as f32 * 1.15 + (time * 0.7).sin() * 16.0 + i as f32 * 4.0;
            let glow = 0.58 + 0.10 * ((time * 1.8 + col as f32 * 0.11).sin());
            let color = if app.reduced {
                BLUE
            } else {
                hsl(hue, 0.58, glow)
            };
            spans.push(Span::styled(ch.to_string(), bold(color)));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_tagline(f: &mut Frame, area: Rect, app: &Landing) {
    let t = motion::elapsed_frac(app.opened, 1400);
    let width = TAGLINE.chars().count().max(8);
    let text = if app.reduced {
        pad_cells(TAGLINE, width)
    } else {
        decrypt(TAGLINE, width, ((t - 0.35) / 0.65).clamp(0.0, 1.0))
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ", fg(DIM)),
            Span::styled(text, fg(TEAL)),
        ])),
        area,
    );
}

fn draw_sparkline(f: &mut Frame, area: Rect, app: &Landing) {
    let w = area.width.saturating_sub(2) as usize;
    let cells = if app.reduced {
        pad_cells("", w.min(48))
    } else {
        let t = (app.opened.elapsed().as_secs_f32() / 1.15).clamp(0.0, 1.4);
        burst_cells(0x5359_4441, t, w.min(48))
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ", fg(DIM)),
            Span::styled(cells, fg(LAVENDER)),
        ])),
        area,
    );
}

fn draw_path(f: &mut Frame, area: Rect, app: &Landing) {
    let flashing = app
        .flash
        .map(|s| s.elapsed() < Duration::from_millis(420))
        .unwrap_or(false);
    let border = if flashing { ROSE } else { DIM };
    let block = Block::default().style(Style::default().bg(SURFACE).fg(border));
    f.render_widget(block, area);

    let inner = inset(area, 1, 0);
    let mut shown = app.input.clone();
    if app.caret && !app.overlay && !app.reduced {
        shown.push('▊');
    } else if app.input.is_empty() {
        shown.push_str("path/to/file  [args]");
    }
    let prompt_color = if flashing { ROSE } else { GREEN };
    let text_color = if app.input.is_empty() { MUTED } else { TEXT };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ▸ ", fg(prompt_color)),
            Span::styled(shown, fg(text_color)),
        ])),
        inner,
    );
}

fn draw_menu(f: &mut Frame, area: Rect, app: &Landing) {
    let mut lines = vec![Line::from("")];
    if let Some((_, msg)) = &app.notice {
        lines.push(Line::from(Span::styled(format!("  {msg}"), fg(PEACH))));
        lines.push(Line::from(""));
    }
    for (i, item) in Item::ALL.iter().enumerate() {
        let dist = (app.focus.pos - i as f32).abs();
        let glow = (1.0 - dist).clamp(0.0, 1.0);
        let color = lerp_color(MUTED, BLUE, glow);
        let mark = if glow > 0.72 { "◆" } else { "◇" };
        let key = format!(" {} ", item.key());
        lines.push(Line::from(vec![
            Span::styled(format!("  {mark}  "), fg(color)),
            Span::styled(
                key,
                Style::default()
                    .fg(if glow > 0.72 { INK } else { MUTED })
                    .bg(if glow > 0.72 { BLUE } else { SURFACE }),
            ),
            Span::styled(format!("  {}", item.label()), bold(color)),
        ]));
        if glow > 0.55 {
            lines.push(Line::from(Span::styled(
                format!("         {}", item.hint()),
                fg(lerp_color(DIM, MUTED, glow)),
            )));
        }
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_suggestions(f: &mut Frame, area: Rect, app: &Landing) {
    if area.height == 0 {
        return;
    }
    let mut lines = vec![Line::from(Span::styled(
        "  suggested paths  ↑↓ choose · tab complete",
        fg(DIM),
    ))];
    if app.suggestions.is_empty() {
        lines.push(Line::from(Span::styled("    no matching paths here", fg(MUTED))));
    }
    for (index, suggestion) in app.suggestions.iter().enumerate() {
        let selected = index == app.selected_suggestion;
        let style = if selected { bold(BLUE) } else { fg(MUTED) };
        lines.push(Line::from(Span::styled(
            format!("  {} {suggestion}", if selected { "▸" } else { " " }),
            style,
        )));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_rain(f: &mut Frame, area: Rect, app: &Landing, lane: u16) {
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);
    if area.width == 0 || area.height == 0 {
        return;
    }
    let t = app.opened.elapsed().as_secs_f32();
    let mut lines = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let mut spans = Vec::with_capacity(area.width as usize);
        for x in 0..area.width {
            let (ch, color) = rain_cell(app, lane, x, y, area.height, t);
            spans.push(Span::styled(ch.to_string(), fg(color)));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn rain_cell(
    app: &Landing,
    lane: u16,
    x: u16,
    y: u16,
    height: u16,
    t: f32,
) -> (char, ratatui::style::Color) {
    let seed = (lane as u64)
        .wrapping_mul(0x9E37)
        .wrapping_add(x as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(y as u64);
    if app.reduced {
        let star = STARS[(seed as usize) % STARS.len()];
        return (star, DIM);
    }
    let col_speed = 6.0 + ((seed >> 8) % 11) as f32;
    let head = ((t * col_speed) + ((seed >> 16) % 40) as f32) % (height as f32 + 12.0);
    let dist = (y as f32 - head + height as f32 + 12.0) % (height as f32 + 12.0);
    let trail = 9.0 + ((seed >> 5) % 5) as f32;
    if dist < trail {
        let idx = ((seed as usize) + (t * 9.0) as usize + y as usize) % RAIN.len();
        let ch = RAIN[idx];
        let fade = 1.0 - (dist / trail);
        let color = if dist < 1.15 {
            TEXT
        } else if fade > 0.55 {
            hsl(154.0 + (t * 12.0).sin() * 10.0, 0.55, 0.28 + fade * 0.42)
        } else {
            hsl(210.0, 0.25, 0.16 + fade * 0.18)
        };
        (ch, color)
    } else if seed.is_multiple_of(23) {
        let star = STARS[((seed >> 3) as usize + (t * 2.0) as usize) % (STARS.len() - 1)];
        (
            star,
            lerp_color(DIM, LAVENDER, 0.25 + 0.2 * (t * 1.7 + x as f32).sin()),
        )
    } else {
        (' ', BG)
    }
}

fn draw_footer(f: &mut Frame, area: Rect, app: &Landing) {
    f.render_widget(Block::default().style(Style::default().bg(SURFACE)), area);
    let hint = if app.overlay {
        "  esc close overlay"
    } else if app.typing() {
        "  ↑↓ choose path   tab complete   enter run/complete   esc clear"
    } else {
        "  type a path + enter   ? commands   q quit"
    };
    f.render_widget(Paragraph::new(Span::styled(hint, fg(DIM))), area);
}

fn draw_overlay(f: &mut Frame, area: Rect) {
    let w = area.width.clamp(36, 64);
    let h = area.height.clamp(12, 20);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let box_area = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    f.render_widget(Clear, box_area);
    let block = Block::bordered()
        .title(" commands ")
        .style(Style::default().bg(SURFACE).fg(BLUE));
    let inner = block.inner(box_area);
    f.render_widget(block, box_area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("  this screen", bold(YELLOW))),
        Line::from(Span::styled(
            "  type a path + enter     run in the viewer",
            fg(TEXT),
        )),
        Line::from(Span::styled(
            "  ↑↓ choose · tab complete  select a suggested path",
            fg(TEXT),
        )),
        Line::from(Span::styled(
            "  ?                       this overlay",
            fg(TEXT),
        )),
        Line::from(Span::styled("  q  esc                  quit", fg(TEXT))),
        Line::from(""),
        Line::from(Span::styled("  CLI", bold(PEACH))),
        Line::from(Span::styled(
            "  sysdag <file> [args]    run, then the graph",
            fg(MUTED),
        )),
        Line::from(Span::styled(
            "  sysdag train <file>     write a baseline",
            fg(MUTED),
        )),
        Line::from(Span::styled(
            "  sysdag monitor <file>   score against it",
            fg(MUTED),
        )),
        Line::from(Span::styled(
            "  sysdag doctor           host check",
            fg(MUTED),
        )),
        Line::from(Span::styled(
            "  --plain  --json         skip the app",
            fg(MUTED),
        )),
        Line::from(""),
        Line::from(Span::styled("  esc closes", fg(DIM))),
    ];
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inset(inner, 1, 0),
    );
}

fn intro_effect() -> Effect {
    fx::sequence(&[
        fx::parallel(&[
            fx::coalesce((620, Interpolation::SineOut)).with_pattern(DissolvePattern::new()),
            fx::evolve_into(EvolveSymbolSet::Shaded, (640, Interpolation::QuadOut))
                .with_pattern(RadialPattern::center().with_transition_width(12.0)),
        ]),
        fx::sweep_in(
            Motion::LeftToRight,
            16,
            0,
            theme::BG,
            (380, Interpolation::QuadOut),
        ),
        fx::timed_never_complete(
            FxDuration::from_millis(260),
            Glitch::builder()
                .cell_glitch_ratio(0.06)
                .action_start_delay_ms(0u32..50)
                .action_ms(40u32..150)
                .build()
                .into_effect(),
        ),
    ])
}

fn spark_effect() -> Effect {
    fx::delay(
        820,
        fx::parallel(&[
            fx::explode(14.0, 3.2, (520, Interpolation::ExpoOut)),
            fx::fade_to_fg(theme::BG, (520, Interpolation::QuadOut)),
        ]),
    )
}

fn ambient_effect() -> Effect {
    fx::repeating(fx::ping_pong(fx::hsl_shift_fg(
        [18.0, 10.0, 7.0],
        (2600, Interpolation::SineInOut),
    )))
}

fn logo_width() -> usize {
    LOGO.iter().map(|s| s.chars().count()).max().unwrap_or(48)
}

fn rain_width(total: u16) -> u16 {
    if total >= 78 {
        10
    } else if total >= 62 {
        8
    } else if total >= 48 {
        5
    } else {
        0
    }
}

fn logo_band(stage: Rect) -> Rect {
    Rect {
        x: stage.x,
        y: stage.y.saturating_add(1),
        width: stage.width,
        height: (LOGO.len() as u16 + 1).min(stage.height.saturating_sub(2)),
    }
}

fn spark_band(stage: Rect) -> Rect {
    let y = stage
        .y
        .saturating_add(LOGO.len() as u16 + 3)
        .min(stage.y.saturating_add(stage.height.saturating_sub(1)));
    Rect {
        x: stage.x,
        y,
        width: stage.width,
        height: 1.min(stage.height),
    }
}

fn inset(area: Rect, x: u16, y: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(x),
        y: area.y.saturating_add(y),
        width: area.width.saturating_sub(x.saturating_mul(2)),
        height: area.height.saturating_sub(y.saturating_mul(2)),
    }
}

pub fn parse_run_line(input: &str) -> Option<(PathBuf, Vec<String>)> {
    let mut parts = input.split_whitespace();
    let path = expand_home(Path::new(parts.next()?));
    let args = parts.map(str::to_string).collect();
    Some((path, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_path_and_args() {
        let (path, args) = parse_run_line("/tmp/target.sh clean extra").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/target.sh"));
        assert_eq!(args, vec!["clean", "extra"]);
    }

    #[test]
    fn blank_line_is_none() {
        assert!(parse_run_line("   ").is_none());
        assert!(parse_run_line("").is_none());
    }
}
