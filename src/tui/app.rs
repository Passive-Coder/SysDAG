use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::Config;
use crate::detector::DecisionRecord;
use crate::event::TraceEvent;
use crate::graph::GraphRecord;
use crate::pipeline::{analyze_path_opts, Mode, RunReport};

use super::motion::{self, Spring};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Graph,
    Events,
    Inspect,
}

impl View {
    pub const ALL: [View; 4] = [View::Overview, View::Graph, View::Events, View::Inspect];

    pub fn title(self) -> &'static str {
        match self {
            View::Overview => "overview",
            View::Graph => "graph",
            View::Events => "events",
            View::Inspect => "inspect",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            View::Overview => "score and reasons",
            View::Graph => "syscall dependency tree",
            View::Events => "captured kernel events",
            View::Inspect => "node and neighbors",
        }
    }

    pub fn next(self) -> Self {
        match self {
            View::Overview => View::Graph,
            View::Graph => View::Events,
            View::Events => View::Inspect,
            View::Inspect => View::Overview,
        }
    }

    pub fn from_digit(c: char) -> Option<Self> {
        match c {
            '1' => Some(View::Overview),
            '2' => Some(View::Graph),
            '3' => Some(View::Events),
            '4' => Some(View::Inspect),
            _ => None,
        }
    }

    pub fn from_letter(c: char) -> Option<Self> {
        match c {
            'o' => Some(View::Overview),
            'g' => Some(View::Graph),
            'e' => Some(View::Events),
            'i' => Some(View::Inspect),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Session {
    pub path: PathBuf,
    pub mode: Mode,
    pub cfg: Config,
    pub work: PathBuf,
    pub baseline_dir: PathBuf,
    pub target_args: Vec<String>,
    pub identity: Option<String>,
    /// Monitor even when the baseline fails compatibility checks.
    pub allow_mismatch: bool,
}

impl Session {
    pub fn target_label(&self) -> String {
        self.path.display().to_string()
    }

    pub fn mode_label(&self) -> &'static str {
        match self.mode {
            Mode::Train => "train",
            Mode::Monitor => "monitor",
            Mode::Auto => "run",
        }
    }
}

pub enum Analysis {
    Pending,
    Ready(Box<RunReport>),
    Failed(String),
}

pub enum FilterMode {
    All,
    NetOnly,
    FileOnly,
    HotOnly,
}

impl FilterMode {
    pub fn next(&self) -> Self {
        match self {
            FilterMode::All => FilterMode::NetOnly,
            FilterMode::NetOnly => FilterMode::FileOnly,
            FilterMode::FileOnly => FilterMode::HotOnly,
            FilterMode::HotOnly => FilterMode::All,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            FilterMode::All => "ALL",
            FilterMode::NetOnly => "NETWORK",
            FilterMode::FileOnly => "FILES",
            FilterMode::HotOnly => "HOT",
        }
    }
}

pub struct App {
    pub session: Session,
    pub analysis: Analysis,
    pub events: Vec<TraceEvent>,
    pub view: View,
    pub window: usize,
    pub cursor: usize,
    pub scroll: u16,
    pub quit: bool,
    pub reduced: bool,
    pub meter: Spring,
    pub focus: Spring,
    pub displayed_score: f32,
    pub target_score: f32,
    pub brand_started: Instant,
    pub heading_started: Instant,
    pub rows_started: Instant,
    pub burst_started: Option<Instant>,
    pub burst_seed: u64,
    pub notice: Option<(Instant, String)>,
    pub opened: Instant,
    pub frame_dt: Duration,
    pub fx: Option<tachyonfx::Effect>,
    rx: Receiver<Result<RunReport, String>>,
    pub filter: FilterMode,
}

impl App {
    pub fn new(session: Session) -> Self {
        let reduced = motion::reduced_motion();
        let (tx, rx) = mpsc::channel();
        let job = session.clone();
        thread::spawn(move || {
            let result = analyze_path_opts(
                &job.path,
                job.mode,
                &job.cfg,
                &job.work,
                &job.baseline_dir,
                &job.target_args,
                true,
                job.identity.as_deref(),
                crate::pipeline::AnalyzeOpts {
                    allow_mismatch: job.allow_mismatch,
                },
            )
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
        });

        let mut app = Self {
            session,
            analysis: Analysis::Pending,
            events: Vec::new(),
            view: View::Overview,
            window: 0,
            cursor: 0,
            scroll: 0,
            quit: false,
            reduced,
            meter: Spring::new(0.0),
            focus: Spring::new(1.0),
            displayed_score: 0.0,
            target_score: 0.0,
            brand_started: Instant::now(),
            heading_started: Instant::now(),
            rows_started: Instant::now(),
            burst_started: None,
            burst_seed: 0,
            notice: None,
            opened: Instant::now(),
            frame_dt: Duration::from_millis(16),
            fx: None,
            rx,
            filter: FilterMode::All,
        };
        app.focus.set(0.0);
        if !reduced {
            app.fx = Some(open_effect());
        }
        app
    }

    pub fn poll_analysis(&mut self) {
        if !matches!(self.analysis, Analysis::Pending) {
            return;
        }
        match self.rx.try_recv() {
            Ok(Ok(report)) => self.apply_report(report),
            Ok(Err(err)) => {
                self.analysis = Analysis::Failed(err);
                self.heading_started = Instant::now();
                self.rows_started = Instant::now();
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                if matches!(self.analysis, Analysis::Pending) {
                    self.analysis = Analysis::Failed("analysis thread stopped".into());
                }
            }
        }
    }

    fn apply_report(&mut self, report: RunReport) {
        self.events = load_events(&report.run_dir);
        let (score, burst) = initial_score(&report);
        self.target_score = score as f32;
        if self.reduced {
            self.meter.snap(self.target_score);
            self.displayed_score = self.target_score;
        } else {
            self.meter.set(self.target_score);
            self.fx = Some(arrive_effect(&report));
            if burst {
                self.burst_started = Some(Instant::now());
                self.burst_seed = report.events as u64 ^ 0x9E37_79B9;
            }
        }
        self.heading_started = Instant::now();
        self.rows_started = Instant::now();
        self.focus.snap(1.0);
        self.focus.set(0.0);
        self.analysis = Analysis::Ready(Box::new(report));
    }

    pub fn tick(&mut self, dt: Duration) {
        self.frame_dt = dt;
        let secs = dt.as_secs_f32();
        if self.reduced {
            self.meter.snap(self.target_score);
            self.displayed_score = self.target_score;
            self.focus.snap(self.focus.target);
            return;
        }
        self.meter.step(secs);
        self.focus.step(secs);
        let toward = self.target_score - self.displayed_score;
        self.displayed_score += toward * (1.0 - (-secs * 7.0).exp());
        if toward.abs() < 0.0005 {
            self.displayed_score = self.target_score;
        }
        if let Some(start) = self.burst_started {
            if start.elapsed() > Duration::from_millis(520) {
                self.burst_started = None;
            }
        }
        if let Some(fx) = &self.fx {
            if !fx.running() {
                self.fx = None;
            }
        }
    }

    pub fn busy(&self) -> bool {
        if matches!(self.analysis, Analysis::Pending) {
            return true;
        }
        if self.reduced {
            return false;
        }
        let brand = motion::elapsed_frac(self.brand_started, 720) < 1.0;
        let heading = motion::elapsed_frac(self.heading_started, 520) < 1.0;
        let rows = motion::elapsed_frac(self.rows_started, 900) < 1.0;
        let fx = self.fx.as_ref().is_some_and(|e| e.running());
        brand
            || heading
            || rows
            || fx
            || !self.meter.settled()
            || !self.focus.settled()
            || (self.displayed_score - self.target_score).abs() > 0.0005
            || self.burst_started.is_some()
    }

    pub fn report(&self) -> Option<&RunReport> {
        match &self.analysis {
            Analysis::Ready(r) => Some(r),
            _ => None,
        }
    }

    pub fn encoded_len(&self) -> usize {
        self.report().map(|r| r.encoded.len().max(1)).unwrap_or(1)
    }

    pub fn decision(&self) -> Option<&DecisionRecord> {
        self.report()?.decisions.get(self.window)
    }

    pub fn graph(&self) -> Option<&GraphRecord> {
        self.report()?.encoded.get(self.window).map(|e| &e.graph)
    }

    pub fn resolved_mode(&self) -> Mode {
        self.report().map(|r| r.mode).unwrap_or(self.session.mode)
    }

    pub fn set_view(&mut self, view: View) {
        if self.view == view {
            return;
        }
        self.view = view;
        self.scroll = 0;
        self.heading_started = Instant::now();
        self.rows_started = Instant::now();
        if !self.reduced {
            self.focus.snap(1.0);
            self.focus.set(0.0);
            if matches!(self.analysis, Analysis::Ready(_)) {
                self.fx = Some(view_sweep());
            }
        }
    }

    pub fn move_window(&mut self, delta: i32) {
        let n = self.encoded_len() as i32;
        self.window = (self.window as i32 + delta).rem_euclid(n) as usize;
        self.cursor = 0;
        self.scroll = 0;
        self.rows_started = Instant::now();
        self.heading_started = Instant::now();
        if let Some(d) = self.decision() {
            self.target_score = d.score as f32;
            if self.reduced {
                self.meter.snap(self.target_score);
                self.displayed_score = self.target_score;
            } else {
                self.meter.set(self.target_score);
                self.fx = Some(view_sweep());
            }
        }
    }

    pub fn move_cursor(&mut self, delta: i32) {
        let n = self.graph().map(|g| g.nodes.len()).unwrap_or(0) as i32;
        if n == 0 {
            return;
        }
        self.cursor = (self.cursor as i32 + delta).rem_euclid(n) as usize;
    }

    pub fn row_alpha(&self, index: usize) -> f32 {
        if self.reduced {
            return 1.0;
        }
        let delay = index as f32 * 0.028;
        let t = self.rows_started.elapsed().as_secs_f32() - delay;
        motion::ease_out(t / 0.18)
    }

    pub fn brand_text(&self, width: usize) -> String {
        let target = motion::pad_cells("SYSDAG", width);
        if self.reduced {
            return target;
        }
        motion::decrypt(
            "SYSDAG",
            width,
            motion::elapsed_frac(self.brand_started, 720),
        )
    }

    pub fn heading_text(&self, title: &str, width: usize) -> String {
        if self.reduced {
            return motion::pad_cells(title, width);
        }
        motion::decrypt(
            title,
            width,
            motion::elapsed_frac(self.heading_started, 480),
        )
    }

    pub fn exit_code(&self) -> i32 {
        match &self.analysis {
            Analysis::Failed(_) => 1,
            Analysis::Ready(r) => {
                if r.decisions.iter().any(|d| d.decision == "ANOMALOUS") {
                    2
                } else {
                    0
                }
            }
            Analysis::Pending => 0,
        }
    }
}

fn load_events(run_dir: &Path) -> Vec<TraceEvent> {
    let Ok(text) = std::fs::read_to_string(run_dir.join("events.jsonl")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn initial_score(report: &RunReport) -> (f64, bool) {
    if report.mode == Mode::Train {
        return (0.0, true);
    }
    let d = report.decisions.first();
    let score = d.map(|d| d.score).unwrap_or(0.0);
    let burst = d
        .map(|d| d.decision == "NORMAL" && d.exact_known)
        .unwrap_or(false);
    (score, burst)
}

fn open_effect() -> tachyonfx::Effect {
    use tachyonfx::{fx, Interpolation, Motion};
    fx::sequence(&[
        fx::coalesce((420, Interpolation::SineOut)),
        fx::sweep_in(
            Motion::LeftToRight,
            10,
            0,
            super::theme::BG,
            (280, Interpolation::QuadOut),
        ),
    ])
}

fn arrive_effect(report: &RunReport) -> tachyonfx::Effect {
    use tachyonfx::{fx, Interpolation, Motion};
    let coalesce = fx::coalesce((380, Interpolation::SineOut));
    if report.mode == Mode::Train {
        return fx::sequence(&[
            coalesce,
            fx::sweep_in(
                Motion::LeftToRight,
                14,
                0,
                super::theme::BG,
                (320, Interpolation::QuadOut),
            ),
        ]);
    }
    if report.decisions.iter().any(|d| d.decision == "ANOMALOUS") {
        return fx::sequence(&[
            coalesce,
            fx::hsl_shift_fg([14.0, 8.0, 5.0], (640, Interpolation::SineInOut)),
        ]);
    }
    fx::sequence(&[
        coalesce,
        fx::sweep_in(
            Motion::LeftToRight,
            8,
            0,
            super::theme::BG,
            (260, Interpolation::QuadOut),
        ),
    ])
}

fn view_sweep() -> tachyonfx::Effect {
    use tachyonfx::{fx, Interpolation, Motion};
    fx::sweep_in(
        Motion::LeftToRight,
        8,
        0,
        super::theme::BG,
        (220, Interpolation::QuadOut),
    )
}
