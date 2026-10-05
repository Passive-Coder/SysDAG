use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;
use tachyonfx::{Duration as FxDuration, EffectRenderer};

use crate::graph::GraphRecord;
use crate::pipeline::Mode;

use super::app::{Analysis, App, View};
use super::motion::{self, burst_cells, lerp_color, pad_cells, sparkline};
use super::theme::{
    self, bold, fg, verdict_color, BG, BLUE, DIM, GREEN, LAVENDER, MUTED, PEACH, RAIL, ROSE,
    SURFACE, TEAL, TEXT,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());

    let cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(24)])
        .split(cols[1]);

    draw_header(f, cols[0], app);
    draw_rail(f, body[0], app);
    draw_workspace(f, body[1], app);
    draw_footer(f, cols[2], app);

    if let Some(fx) = &mut app.fx {
        if fx.running() {
            let ms = app.frame_dt.as_millis().min(50) as u32;
            f.render_effect(fx, body[1], FxDuration::from_millis(ms));
        }
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(Block::default().style(Style::default().bg(SURFACE)), area);

    let brand = app.brand_text(8);
    let mode = match app.resolved_mode() {
        Mode::Train => "TRAIN",
        Mode::Monitor => "MONITOR",
        Mode::Auto => "RUN",
    };
    let status = match &app.analysis {
        Analysis::Pending => "tracing",
        Analysis::Ready(r) if r.analysis_error.is_some() => "analysis error",
        Analysis::Ready(r) if r.target_exit_code.is_some() => "target exit",
        Analysis::Ready(_) => "live",
        Analysis::Failed(_) => "error",
    };
    let status_color = match &app.analysis {
        Analysis::Pending => shimmer(app.opened.elapsed().as_secs_f32()),
        Analysis::Ready(r) if r.analysis_error.is_some() => ROSE,
        Analysis::Ready(r) if r.target_exit_code.is_some() => PEACH,
        Analysis::Ready(_) => GREEN,
        Analysis::Failed(_) => ROSE,
    };

    let args = if app.session.target_args.is_empty() {
        String::new()
    } else {
        format!("  {}", app.session.target_args.join(" "))
    };

    let row0 = Line::from(vec![
        Span::styled(" ", fg(TEXT)),
        Span::styled(brand, bold(BLUE)),
        Span::styled(" · process graph", fg(MUTED)),
        Span::styled("    ", fg(DIM)),
        Span::styled(
            format!(" {mode} "),
            Style::default()
                .fg(theme::INK)
                .bg(BLUE)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ),
        Span::styled("  ", fg(DIM)),
        Span::styled("● ", fg(status_color)),
        Span::styled(status, fg(status_color)),
    ]);

    let row1 = Line::from(vec![
        Span::styled("  ", fg(DIM)),
        Span::styled(app.session.target_label(), fg(TEXT)),
        Span::styled(args, fg(LAVENDER)),
        Span::styled("    micro-VM", fg(DIM)),
    ]);

    let rule = Line::from(Span::styled(
        "─".repeat(area.width as usize),
        fg(DIM).bg(SURFACE),
    ));

    f.render_widget(Paragraph::new(vec![row0, row1, rule]), area);
}

fn draw_rail(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(Block::default().style(Style::default().bg(RAIL)), area);

    let inner = inset(area, 1, 0);
    let mut lines = vec![
        Line::from(Span::styled("  SESSION", bold(DIM))),
        Line::from(""),
        Line::from(vec![
            Span::styled("  host   ", fg(DIM)),
            Span::styled("docker", fg(TEAL)),
        ]),
        Line::from(vec![
            Span::styled("  window ", fg(DIM)),
            Span::styled(
                format!("{}/{}", app.window + 1, app.encoded_len()),
                fg(TEXT),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled("  VIEWS", bold(DIM))),
        Line::from(""),
    ];

    for (i, view) in View::ALL.iter().enumerate() {
        let selected = app.view == *view;
        let pulse = if selected { app.focus.pos } else { 0.0 };
        let color = if selected {
            lerp_color(BLUE, LAVENDER, pulse)
        } else {
            MUTED
        };
        let mark = if selected { "◆" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(format!("  {mark} "), fg(color)),
            Span::styled(format!("{} {}", i + 1, view.title()), bold(color)),
        ]));
        if selected {
            lines.push(Line::from(Span::styled(
                format!("      {}", view.hint()),
                fg(DIM),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  PIPELINE", bold(DIM))));
    lines.push(Line::from(""));
    match &app.analysis {
        Analysis::Pending => {
            let phase = phase_label(app.opened.elapsed().as_secs_f32());
            lines.push(Line::from(Span::styled(
                format!("  {phase}"),
                fg(shimmer(app.opened.elapsed().as_secs_f32())),
            )));
        }
        Analysis::Ready(r) => {
            let events = r.events.to_string();
            let windows = r.encoded.len().to_string();
            let nodes = app.graph().map(|g| g.nodes.len().to_string());
            let edges = app.graph().map(|g| g.edges.len().to_string());
            lines.push(chip("events", events));
            lines.push(chip("windows", windows));
            if let Some(nodes) = nodes {
                lines.push(chip("nodes", nodes));
            }
            if let Some(edges) = edges {
                lines.push(chip("edges", edges));
            }
            if let Some(stats) = &r.parse_stats {
                let loss = stats.quality_loss();
                let (label, color) = if loss == 0 {
                    ("clean".into(), GREEN)
                } else {
                    let rate = if stats.lines > 0 {
                        format!(" {:.2}%", loss as f64 / stats.lines as f64 * 100.0)
                    } else {
                        String::new()
                    };
                    (
                        format!(
                            "degraded u={} m={} l={}{rate}",
                            stats.unknown_syscalls,
                            stats.malformed_records,
                            stats.lost_events_estimate
                        ),
                        PEACH,
                    )
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<8}", "capture"), fg(DIM)),
                    Span::styled(label, fg(color)),
                ]));
            }
            if r.analysis_error.is_some() {
                lines.push(Line::from(Span::styled("  analysis failed", fg(ROSE))));
            }
            if let Some(code) = r.target_exit_code {
                lines.push(Line::from(Span::styled(
                    format!("  target exit {code}"),
                    fg(PEACH),
                )));
            }
        }
        Analysis::Failed(_) => {
            lines.push(Line::from(Span::styled("  failed", fg(ROSE))));
        }
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn chip(k: &str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {k:<8}"), fg(DIM)),
        Span::styled(v, fg(TEXT)),
    ])
}

fn draw_workspace(f: &mut Frame, area: Rect, app: &App) {
    if app.view == View::Graph && matches!(app.analysis, Analysis::Ready(_)) {
        super::graph_view::draw(f, area, app);
        return;
    }
    let lines = match &app.analysis {
        Analysis::Pending => pending_doc(app),
        Analysis::Failed(err) => failed_doc(app, err),
        Analysis::Ready(r) => match app.view {
            View::Overview if r.analysis_error.is_some() => {
                capture_only_doc(app, r.analysis_error.as_deref().unwrap_or_default())
            }
            View::Overview => overview_doc(app),
            View::Graph => graph_doc(app),
            View::Events => events_doc(app),
            View::Inspect => inspect_doc(app),
        },
    };
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(Block::default().style(Style::default().bg(SURFACE)), area);
    let view = app.view.title();
    let hint = if app
        .notice
        .as_ref()
        .is_some_and(|(opened, _)| opened.elapsed().as_secs() < 3)
    {
        format!("  {}", app.notice.as_ref().unwrap().1)
    } else {
        format!("  {view}   tab views   1-4 jump   j/k move   [ ] window   v browser   q quit")
    };
    f.render_widget(Paragraph::new(Span::styled(hint, fg(DIM))), area);
}

fn pending_doc(app: &App) -> Vec<Line<'static>> {
    let heading = app.heading_text("tracing", 10);
    let t = app.opened.elapsed().as_secs_f32();
    let wave = 0.22 + 0.18 * (0.5 + 0.5 * (t * 2.4).sin());
    let mut bar = vec![Span::styled("  ", fg(DIM))];
    bar.extend(meter_line(24, wave as f64, TEAL));
    vec![
        Line::from(Span::styled(format!("  {heading}"), bold(TEAL))),
        Line::from(""),
        Line::from(Span::styled(
            "  the sandbox is compiling and tracing the process",
            fg(MUTED),
        )),
        Line::from(""),
        Line::from(bar),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", phase_label(t)),
            fg(shimmer(t)),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  layout stays put. results coalesce in when the graph is ready.",
            fg(DIM),
        )),
    ]
}

fn failed_doc(app: &App, err: &str) -> Vec<Line<'static>> {
    let heading = app.heading_text("failed", 8);
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(ROSE))),
        Line::from(""),
        Line::from(Span::styled("  the run did not produce a graph", fg(MUTED))),
        Line::from(""),
    ];
    for part in err.lines() {
        lines.push(Line::from(Span::styled(format!("  {part}"), fg(TEXT))));
    }
    lines
}

fn capture_only_doc(app: &App, err: &str) -> Vec<Line<'static>> {
    let heading = app.heading_text("capture only", 12);
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(ROSE))),
        Line::from(""),
        Line::from(Span::styled(
            "  Trace captured, but analysis could not finish.",
            fg(TEXT),
        )),
        Line::from(Span::styled(
            "  Graph, events, and inspect are available in views 2–4.",
            fg(TEAL),
        )),
        Line::from(""),
        Line::from(Span::styled("  analysis error", bold(PEACH))),
    ];
    for part in err.lines() {
        lines.push(Line::from(Span::styled(format!("  {part}"), fg(TEXT))));
    }
    if let Some(code) = app.report().and_then(|r| r.target_exit_code) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  Traced program exited with status {code}."),
            fg(PEACH),
        )));
    }
    lines
}

fn overview_doc(app: &App) -> Vec<Line<'static>> {
    let heading = app.heading_text("overview", 10);
    let (label, color, extra) = status(app);
    let fill = app.meter.pos.clamp(0.0, 1.0);
    let score = format!("{:>5.3}", app.displayed_score);
    let mut meter = vec![Span::styled(format!("  {label:<10}"), bold(color))];
    meter.extend(meter_line(24, fill as f64, color));
    meter.push(Span::styled(format!("  {score}"), fg(TEXT)));
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(BLUE))),
        Line::from(""),
        fade(0, app, meter, color),
        fade(
            1,
            app,
            vec![Span::styled(format!("            {extra}"), fg(MUTED))],
            MUTED,
        ),
    ];

    if let Some(code) = app.report().and_then(|r| r.target_exit_code) {
        lines.push(Line::from(Span::styled(
            format!("  Traced program exited with status {code}; capture succeeded."),
            fg(PEACH),
        )));
    }

    if let Some(start) = app.burst_started {
        let cells = burst_cells(app.burst_seed, start.elapsed().as_secs_f32() / 0.52, 24);
        lines.push(Line::from(vec![
            Span::styled("            ", fg(DIM)),
            Span::styled(cells, fg(TEAL)),
        ]));
    } else {
        lines.push(Line::from(""));
    }

    let scores: Vec<f64> = app
        .report()
        .map(|r| {
            if r.decisions.is_empty() {
                vec![0.08]
            } else {
                r.decisions.iter().map(|d| d.score).collect()
            }
        })
        .unwrap_or_else(|| vec![0.08]);
    let spark = sparkline(&scores, 16);
    lines.push(fade(
        2,
        app,
        vec![
            Span::styled("  windows  ", fg(DIM)),
            Span::styled(spark, fg(LAVENDER)),
        ],
        LAVENDER,
    ));
    lines.push(Line::from(""));

    if let Some(d) = app.decision() {
        lines.push(fade(
            3,
            app,
            vec![Span::styled("  why", bold(PEACH))],
            PEACH,
        ));
        lines.push(Line::from(""));
        if d.evidence.is_empty() {
            let note = if d.exact_known {
                "  exact fingerprint of a trained window"
            } else {
                "  no high-risk motif in this window"
            };
            lines.push(fade(4, app, vec![Span::styled(note, fg(MUTED))], MUTED));
        } else {
            for (i, ev) in d.evidence.iter().enumerate() {
                let hot = hot_motif(&ev.motif);
                let mark = if hot { "●" } else { "○" };
                let c = if hot { ROSE } else { TEXT };
                lines.push(fade(
                    4 + i,
                    app,
                    vec![Span::styled(format!("  {mark}  {}", ev.motif), fg(c))],
                    c,
                ));
                if !ev.detail.is_empty() {
                    lines.push(fade(
                        5 + i,
                        app,
                        vec![Span::styled(format!("      {}", ev.detail), fg(MUTED))],
                        MUTED,
                    ));
                }
            }
        }
    } else if app.resolved_mode() == Mode::Train {
        lines.push(fade(
            3,
            app,
            vec![Span::styled(
                "  baseline written from this shape",
                fg(MUTED),
            )],
            MUTED,
        ));
        lines.push(fade(
            4,
            app,
            vec![Span::styled(
                "  run the same file on another workload to compare",
                fg(DIM),
            )],
            DIM,
        ));
    }

    if let Some(r) = app.report() {
        lines.push(Line::from(""));
        lines.push(fade(
            12,
            app,
            vec![Span::styled(
                format!(
                    "  {} events   {} windows   artifacts {}",
                    r.events,
                    r.encoded.len(),
                    r.run_dir.display()
                ),
                fg(DIM),
            )],
            DIM,
        ));
    }
    lines
}

fn graph_doc(app: &App) -> Vec<Line<'static>> {
    let heading = app.heading_text("graph", 8);
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(BLUE))),
        Line::from(Span::styled(
            format!(
                "  hierarchy  ·  filter: {}  ·  f to cycle",
                app.filter.label()
            ),
            fg(DIM),
        )),
        Line::from(vec![
            Span::styled("  ● ", bold(BLUE)),
            Span::styled("file   ", fg(MUTED)),
            Span::styled("● ", bold(GREEN)),
            Span::styled("process   ", fg(MUTED)),
            Span::styled("● ", bold(TEAL)),
            Span::styled("network   ", fg(MUTED)),
            Span::styled("● ", bold(ROSE)),
            Span::styled("risk", fg(ROSE)),
        ]),
        Line::from(""),
    ];
    match app.graph() {
        None => lines.push(Line::from(Span::styled(
            "  no graph in this run",
            fg(MUTED),
        ))),
        Some(g) => {
            let tree = render_tree_filtered(g, &app.filter);
            for (i, line) in tree.into_iter().enumerate() {
                lines.push(fade_line(i, app, line));
            }
        }
    }
    lines
}

fn events_doc(app: &App) -> Vec<Line<'static>> {
    let heading = app.heading_text("events", 8);
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(BLUE))),
        Line::from(""),
    ];
    let g = app.graph();
    let (start, end) = g
        .map(|gr| (gr.window.start_seq, gr.window.end_seq))
        .unwrap_or((0, u64::MAX));
    let scoped: Vec<_> = app
        .events
        .iter()
        .filter(|e| e.seq >= start && e.seq <= end)
        .collect();
    let rows: Vec<_> = if scoped.is_empty() {
        app.events.iter().collect()
    } else {
        scoped
    };
    if rows.is_empty() {
        lines.push(Line::from(Span::styled("  no events captured", fg(MUTED))));
        return lines;
    }
    for (i, e) in rows.into_iter().enumerate() {
        let path = e
            .args
            .path
            .as_deref()
            .or(e.args.fd_path.as_deref())
            .unwrap_or("");
        let ret = e.ret.map(|r| r.to_string()).unwrap_or_else(|| "·".into());
        let hot = e.labels.path_class == "DECOY"
            || e.labels.op.contains("NET_")
            || e.labels.op == "PROCESS_EXEC";
        let c = if hot { ROSE } else { TEXT };
        lines.push(fade(
            i,
            app,
            vec![
                Span::styled(format!("  {:>4}  ", e.seq), fg(DIM)),
                Span::styled(format!("{:<10}  ", e.syscall.name), fg(c)),
                Span::styled(format!("{:>4}  ", ret), fg(MUTED)),
                Span::styled(path.to_string(), fg(if hot { PEACH } else { MUTED })),
            ],
            c,
        ));
    }
    lines
}

fn inspect_doc(app: &App) -> Vec<Line<'static>> {
    let heading = app.heading_text("inspect", 8);
    let mut lines = vec![
        Line::from(Span::styled(format!("  {heading}"), bold(BLUE))),
        Line::from(""),
    ];
    let Some(g) = app.graph() else {
        lines.push(Line::from(Span::styled("  no nodes to inspect", fg(MUTED))));
        return lines;
    };
    if g.nodes.is_empty() {
        lines.push(Line::from(Span::styled("  empty graph", fg(MUTED))));
        return lines;
    }
    let idx = app.cursor.min(g.nodes.len() - 1);
    let node = &g.nodes[idx];
    let label = node_label(node);
    let color = graph_node_color(node);

    lines.push(fade(
        0,
        app,
        vec![
            Span::styled("  node   ", fg(DIM)),
            Span::styled(node.id.clone(), bold(color)),
            Span::styled(format!("   {} / {}", idx + 1, g.nodes.len()), fg(DIM)),
        ],
        color,
    ));
    lines.push(fade(
        1,
        app,
        vec![Span::styled(format!("  {label}"), fg(color))],
        color,
    ));
    lines.push(Line::from(""));
    lines.push(fade(
        2,
        app,
        vec![Span::styled("  fields", bold(PEACH))],
        PEACH,
    ));
    lines.push(Line::from(""));
    for (i, (k, v)) in node.label_fields.iter().enumerate() {
        lines.push(fade(
            3 + i,
            app,
            vec![
                Span::styled(format!("  {k:<14}"), fg(DIM)),
                Span::styled(v.clone(), fg(TEXT)),
            ],
            TEXT,
        ));
    }

    let incoming: Vec<_> = g.edges.iter().filter(|e| e.dst == node.id).collect();
    let outgoing: Vec<_> = g.edges.iter().filter(|e| e.src == node.id).collect();
    lines.push(Line::from(""));
    lines.push(fade(
        12,
        app,
        vec![Span::styled("  connected", bold(LAVENDER))],
        LAVENDER,
    ));
    lines.push(Line::from(""));
    if incoming.is_empty() && outgoing.is_empty() {
        lines.push(fade(
            13,
            app,
            vec![Span::styled("  isolated node", fg(MUTED))],
            MUTED,
        ));
    }
    for (i, e) in incoming.iter().enumerate() {
        let hot = e.edge_type == "BUFFER_FLOW";
        lines.push(fade(
            13 + i,
            app,
            vec![Span::styled(
                format!("  ←  {}   {}", e.edge_type, e.src),
                fg(if hot { ROSE } else { MUTED }),
            )],
            if hot { ROSE } else { MUTED },
        ));
    }
    for (i, e) in outgoing.iter().enumerate() {
        let hot = e.edge_type == "BUFFER_FLOW";
        lines.push(fade(
            16 + i,
            app,
            vec![Span::styled(
                format!("  →  {}   {}", e.edge_type, e.dst),
                fg(if hot { ROSE } else { MUTED }),
            )],
            if hot { ROSE } else { MUTED },
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  j/k walk nodes", fg(DIM))));
    lines
}

fn status(app: &App) -> (&'static str, Color, String) {
    if app.resolved_mode() == Mode::Train {
        return (
            "TRAINED",
            BLUE,
            format!(
                "{} events  ·  {} windows  ·  baseline written",
                app.report().map(|r| r.events).unwrap_or(0),
                app.report().map(|r| r.encoded.len()).unwrap_or(0)
            ),
        );
    }
    match app.decision() {
        Some(d) => {
            let label = match d.decision.as_str() {
                "ANOMALOUS" => "ANOMALOUS",
                "REVIEW" => "REVIEW",
                "NORMAL" => "NORMAL",
                "UNKNOWN" => "UNKNOWN",
                _ => "READY",
            };
            let sim = d
                .nearest_normal
                .as_ref()
                .map(|n| format!("sim {:.2}", n.weighted_jaccard))
                .unwrap_or_else(|| "sim —".into());
            (
                label,
                verdict_color(label),
                format!(
                    "exact {}  ·  {sim}  ·  {} nodes  {} edges",
                    if d.exact_known { "yes" } else { "no" },
                    d.n_nodes,
                    d.n_edges
                ),
            )
        }
        None => ("READY", MUTED, "waiting for a window".into()),
    }
}

fn meter_line(width: usize, fill: f64, color: Color) -> Vec<Span<'static>> {
    let fill = fill.clamp(0.0, 1.0);
    let pos = fill * width as f64;
    let mut spans = Vec::with_capacity(width);
    for i in 0..width {
        let cell = i as f64;
        let t = (pos - cell).clamp(0.0, 1.0) as f32;
        let c = lerp_color(DIM, color, t);
        spans.push(Span::styled("█", fg(c)));
    }
    spans
}

fn fade(index: usize, app: &App, mut spans: Vec<Span<'static>>, target: Color) -> Line<'static> {
    let a = app.row_alpha(index);
    if a >= 0.995 {
        return Line::from(spans);
    }
    for span in &mut spans {
        if let Color::Rgb(_, _, _) = span.style.fg.unwrap_or(target) {
            let from = DIM;
            let to = span.style.fg.unwrap_or(target);
            span.style.fg = Some(lerp_color(from, to, a));
        }
    }
    Line::from(spans)
}

fn fade_line(index: usize, app: &App, line: Line<'static>) -> Line<'static> {
    fade(index, app, line.spans, TEXT)
}

fn render_tree_filtered(g: &GraphRecord, filter: &super::app::FilterMode) -> Vec<Line<'static>> {
    use std::collections::HashSet;

    let nodes: HashMap<&str, &crate::graph::GraphNode> =
        g.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let visible: HashSet<&str> = g
        .nodes
        .iter()
        .filter(|n| match filter {
            super::app::FilterMode::All => true,
            super::app::FilterMode::NetOnly => {
                n.label_fields.get("family").is_some_and(|v| v == "network")
                    || n.label_fields
                        .get("resource_kind")
                        .is_some_and(|v| v == "SOCKET")
            }
            super::app::FilterMode::FileOnly => {
                n.label_fields.get("family").is_some_and(|v| v == "file")
                    || n.label_fields
                        .get("resource_kind")
                        .is_some_and(|v| v == "FILE")
            }
            super::app::FilterMode::HotOnly => is_risk_node(n),
        })
        .map(|n| n.id.as_str())
        .collect();
    if visible.is_empty() {
        return vec![Line::from(Span::styled(
            "  no nodes match this filter",
            fg(MUTED),
        ))];
    }

    let mut kids: HashMap<&str, Vec<&crate::graph::GraphEdge>> = HashMap::new();
    let mut incoming: HashMap<&str, usize> = HashMap::new();
    for edge in &g.edges {
        if visible.contains(edge.src.as_str()) && visible.contains(edge.dst.as_str()) {
            kids.entry(edge.src.as_str()).or_default().push(edge);
            *incoming.entry(edge.dst.as_str()).or_default() += 1;
        }
    }
    for edges in kids.values_mut() {
        edges.sort_by(|a, b| (&a.dst, &a.edge_type).cmp(&(&b.dst, &b.edge_type)));
    }

    // Use the same longest-path hierarchy as the browser viewer. Vertical
    // sections fit a terminal without cutting off deep chains horizontally.
    let mut remaining: HashMap<&str, usize> = visible
        .iter()
        .map(|id| (*id, incoming.get(id).copied().unwrap_or(0)))
        .collect();
    let mut levels: HashMap<&str, usize> = HashMap::new();
    let mut queue = std::collections::VecDeque::new();
    for node in &g.nodes {
        let id = node.id.as_str();
        if visible.contains(id) && remaining.get(id) == Some(&0) {
            levels.insert(id, 0);
            queue.push_back(id);
        }
    }
    while let Some(id) = queue.pop_front() {
        let next = levels.get(id).copied().unwrap_or(0) + 1;
        if let Some(edges) = kids.get(id) {
            for edge in edges {
                let dst = edge.dst.as_str();
                levels
                    .entry(dst)
                    .and_modify(|level| *level = (*level).max(next))
                    .or_insert(next);
                if let Some(count) = remaining.get_mut(dst) {
                    *count -= 1;
                    if *count == 0 {
                        queue.push_back(dst);
                    }
                }
            }
        }
    }
    let mut fallback = levels.values().copied().max().unwrap_or(0) + 1;
    for node in &g.nodes {
        if visible.contains(node.id.as_str()) && !levels.contains_key(node.id.as_str()) {
            levels.insert(node.id.as_str(), fallback);
            fallback += 1;
        }
    }

    let mut ordered: Vec<_> = g
        .nodes
        .iter()
        .filter(|n| visible.contains(n.id.as_str()))
        .collect();
    ordered.sort_by_key(|n| levels.get(n.id.as_str()).copied().unwrap_or(0));
    let mut out = Vec::new();
    let mut shown_level = None;
    for node in ordered {
        let level = levels[&node.id.as_str()];
        if shown_level != Some(level) {
            if !out.is_empty() {
                out.push(Line::from(""));
            }
            out.push(Line::from(Span::styled(
                format!("  layer {level}"),
                bold(DIM),
            )));
            shown_level = Some(level);
        }
        out.push(graph_node_line(node, "  "));
        if let Some(edges) = kids.get(node.id.as_str()) {
            for (index, edge) in edges.iter().enumerate() {
                let color = graph_edge_color(&edge.edge_type);
                let branch = if index + 1 == edges.len() {
                    "└"
                } else {
                    "├"
                };
                out.push(Line::from(vec![
                    Span::styled(format!("    {branch}─"), fg(DIM)),
                    Span::styled(
                        format!(" {} ", edge.edge_type.replace('_', " ").to_lowercase()),
                        fg(color),
                    ),
                    Span::styled("──▶ ", fg(color)),
                    Span::styled(edge.dst.clone(), fg(MUTED)),
                    Span::styled(
                        nodes
                            .get(edge.dst.as_str())
                            .map(|n| format!("  {}", node_label(n)))
                            .unwrap_or_default(),
                        fg(color),
                    ),
                ]));
            }
        }
    }
    out
}

fn graph_node_line(n: &crate::graph::GraphNode, prefix: &str) -> Line<'static> {
    let color = graph_node_color(n);
    let mut spans = vec![
        Span::styled(prefix.to_string(), fg(DIM)),
        Span::styled("● ", bold(color)),
        Span::styled(format!("{}  ", n.id), fg(MUTED)),
        Span::styled(node_label(n), bold(color)),
    ];
    if is_risk_node(n) {
        spans.push(Span::styled("  ! risk", bold(ROSE)));
    }
    Line::from(spans)
}

fn node_label(n: &crate::graph::GraphNode) -> String {
    let op = n.label_fields.get("op").map(|s| s.as_str()).unwrap_or("?");
    let pc = n
        .label_fields
        .get("path_class")
        .map(|s| s.as_str())
        .unwrap_or("");
    if pc.is_empty() || pc == "NONE" {
        op.to_string()
    } else {
        format!("{op}  {pc}")
    }
}

fn is_risk_node(n: &crate::graph::GraphNode) -> bool {
    if n.kind == "anchor" {
        return false;
    }
    let label = node_label(n);
    let op = n.label_fields.get("op").map(String::as_str).unwrap_or("");
    let flags = n
        .label_fields
        .get("flags")
        .map(String::as_str)
        .unwrap_or("");
    ["DECOY", "SHELL", "SYSTEM_CONFIG", "NET_SEND", "NET_SOCKET"]
        .iter()
        .any(|term| label.contains(term))
        || op == "SHELL_EXEC"
        || (op == "FILE_WRITE" && flags == "CREATE_WRITE")
}

fn graph_node_color(n: &crate::graph::GraphNode) -> Color {
    if n.kind == "anchor" {
        MUTED
    } else if is_risk_node(n) {
        ROSE
    } else if n
        .label_fields
        .get("path_class")
        .is_some_and(|v| v == "APP_ROOT")
    {
        GREEN
    } else {
        match n.label_fields.get("resource_kind").map(String::as_str) {
            Some("SOCKET") => TEAL,
            Some("PROCESS") => GREEN,
            Some("PIPE" | "MEMORY") => LAVENDER,
            Some("FILE") => BLUE,
            _ => TEXT,
        }
    }
}

fn graph_edge_color(edge_type: &str) -> Color {
    match edge_type {
        "BUFFER_FLOW" => ROSE,
        "FD_FLOW" => BLUE,
        "PROCESS_FLOW" | "PROC_SPAWN" => GREEN,
        "PIPE_FLOW" => LAVENDER,
        "SCM_RIGHTS" => TEAL,
        _ => MUTED,
    }
}

fn hot_motif(motif: &str) -> bool {
    motif.contains("DECOY")
        || motif.contains("BUFFER_FLOW")
        || motif.contains("SHELL")
        || motif.contains("SYSTEM_CONFIG")
}

fn phase_label(t: f32) -> String {
    let phases = [
        "compiling guest    ",
        "attaching strace   ",
        "building the DAG   ",
        "fingerprinting     ",
    ];
    pad_cells(phases[(t * 0.7) as usize % phases.len()], 20)
}

fn shimmer(t: f32) -> Color {
    motion::hsl(
        198.0 + (t * 40.0).sin() * 14.0,
        0.42,
        0.62 + (t * 3.1).sin() * 0.06,
    )
}

fn inset(area: Rect, x: u16, y: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(x),
        y: area.y.saturating_add(y),
        width: area.width.saturating_sub(x.saturating_mul(2)),
        height: area.height.saturating_sub(y.saturating_mul(2)),
    }
}
