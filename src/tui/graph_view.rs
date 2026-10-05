//! Spatial terminal rendering of the hierarchy in `tools/viewer.html`.

use std::collections::{BTreeMap, HashMap, VecDeque};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::graph::{GraphEdge, GraphNode, GraphRecord};

use super::app::{App, FilterMode};
use super::theme::{BLUE, DIM, GREEN, LAVENDER, MUTED, ROSE, TEAL, TEXT};

const NODE_WIDTH: usize = 16;
const ROW_SPACING: i32 = 9;

pub(super) fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let Some(graph) = app.graph() else {
        frame.render_widget(Paragraph::new("  no graph in this run"), area);
        return;
    };
    let visible = visible_nodes(graph, &app.filter);
    let ids: HashMap<&str, usize> = visible
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect();
    let edges: Vec<&GraphEdge> = graph
        .edges
        .iter()
        .filter(|edge| ids.contains_key(edge.src.as_str()) && ids.contains_key(edge.dst.as_str()))
        .collect();

    let header = vec![
        Line::from(vec![
            Span::styled(
                "  graph",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "  ·  hierarchy  ·  {} nodes / {} edges  ·  filter {}  ·  f cycle",
                    visible.len(),
                    edges.len(),
                    app.filter.label()
                ),
                Style::default().fg(DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ●", Style::default().fg(BLUE)),
            Span::styled(" file   ", Style::default().fg(MUTED)),
            Span::styled("●", Style::default().fg(GREEN)),
            Span::styled(" process   ", Style::default().fg(MUTED)),
            Span::styled("●", Style::default().fg(TEAL)),
            Span::styled(" network   ", Style::default().fg(MUTED)),
            Span::styled("!", Style::default().fg(ROSE)),
            Span::styled(" risk   j/k scroll", Style::default().fg(MUTED)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(header),
        Rect {
            height: area.height.min(2),
            ..area
        },
    );
    if area.height <= 2 || visible.is_empty() {
        if visible.is_empty() && area.height > 2 {
            frame.render_widget(
                Paragraph::new("  no nodes match this filter"),
                Rect {
                    y: area.y + 2,
                    height: 1,
                    ..area
                },
            );
        }
        return;
    }

    let canvas = Rect {
        x: area.x,
        y: area.y + 2,
        width: area.width,
        height: area.height - 2,
    };
    let positions = layout(&visible, &edges, &ids, canvas.width as usize);
    let buffer = frame.buffer_mut();
    for edge in &edges {
        let src = positions[ids[edge.src.as_str()]];
        let dst = positions[ids[edge.dst.as_str()]];
        draw_edge(buffer, canvas, app.scroll as i32, src, dst, edge);
    }
    for (node, &(x, y)) in visible.iter().zip(positions.iter()) {
        draw_node(buffer, canvas, app.scroll as i32, x, y, node);
    }
}

fn visible_nodes<'a>(graph: &'a GraphRecord, filter: &FilterMode) -> Vec<&'a GraphNode> {
    graph
        .nodes
        .iter()
        .filter(|node| match filter {
            FilterMode::All => true,
            FilterMode::NetOnly => {
                node.label_fields
                    .get("family")
                    .is_some_and(|v| v == "network")
                    || node
                        .label_fields
                        .get("resource_kind")
                        .is_some_and(|v| v == "SOCKET")
            }
            FilterMode::FileOnly => {
                node.label_fields.get("family").is_some_and(|v| v == "file")
                    || node
                        .label_fields
                        .get("resource_kind")
                        .is_some_and(|v| v == "FILE")
            }
            FilterMode::HotOnly => is_risk(node),
        })
        .collect()
}

// Same longest-path levels as the D3 hierarchy. Extra rows let a wide level
// fit in a narrow terminal without dropping nodes or edges.
fn layout(
    nodes: &[&GraphNode],
    edges: &[&GraphEdge],
    ids: &HashMap<&str, usize>,
    width: usize,
) -> Vec<(i32, i32)> {
    let mut children = vec![Vec::new(); nodes.len()];
    let mut indegree = vec![0usize; nodes.len()];
    for edge in edges {
        let src = ids[edge.src.as_str()];
        let dst = ids[edge.dst.as_str()];
        children[src].push(dst);
        indegree[dst] += 1;
    }
    let mut remaining = indegree;
    let mut levels = vec![None; nodes.len()];
    let mut queue = VecDeque::new();
    for (index, &count) in remaining.iter().enumerate() {
        if count == 0 {
            levels[index] = Some(0);
            queue.push_back(index);
        }
    }
    while let Some(src) = queue.pop_front() {
        let next = levels[src].unwrap_or(0) + 1;
        for &dst in &children[src] {
            levels[dst] = Some(levels[dst].unwrap_or(0).max(next));
            remaining[dst] -= 1;
            if remaining[dst] == 0 {
                queue.push_back(dst);
            }
        }
    }
    let mut fallback = levels.iter().flatten().copied().max().unwrap_or(0) + 1;
    for level in &mut levels {
        if level.is_none() {
            *level = Some(fallback);
            fallback += 1;
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, level) in levels.into_iter().enumerate() {
        groups.entry(level.unwrap_or(0)).or_default().push(index);
    }
    let card_width = NODE_WIDTH.min(width.saturating_sub(2)).max(1);
    let columns = (width / (card_width + 4)).max(1);
    let mut positions = vec![(0, 0); nodes.len()];
    let mut y = 2;
    for group in groups.values() {
        for row in group.chunks(columns) {
            for (slot, &index) in row.iter().enumerate() {
                let x = ((slot + 1) * width / (row.len() + 1)) as i32;
                positions[index] = (x, y);
            }
            y += ROW_SPACING;
        }
        y += 2;
    }
    positions
}

fn draw_edge(
    buffer: &mut Buffer,
    area: Rect,
    scroll: i32,
    src: (i32, i32),
    dst: (i32, i32),
    edge: &GraphEdge,
) {
    let color = edge_color(&edge.edge_type);
    let start = (src.0, src.1 + 4);
    let end = (dst.0, dst.1 - 1);
    let (mut x, mut y) = start;
    let dx = (end.0 - x).abs();
    let dy = -(end.1 - y).abs();
    let step_x = if x < end.0 { 1 } else { -1 };
    let step_y = if y < end.1 { 1 } else { -1 };
    let mut error = dx + dy;
    let glyph = if dx == 0 {
        "│"
    } else if dy == 0 {
        "─"
    } else if step_x == step_y {
        "╲"
    } else {
        "╱"
    };
    loop {
        cell(buffer, area, scroll, x, y, glyph, color);
        if (x, y) == end {
            break;
        }
        let twice = error * 2;
        if twice >= dy {
            error += dy;
            x += step_x;
        }
        if twice <= dx {
            error += dx;
            y += step_y;
        }
    }
    let arrow = if dst.1 > src.1 {
        "▼"
    } else if dst.1 < src.1 {
        "▲"
    } else {
        "▶"
    };
    cell(buffer, area, scroll, end.0, end.1, arrow, color);
    let label = match edge.edge_type.as_str() {
        "FD_FLOW" => "FD",
        "PROCESS_FLOW" => "PROCESS",
        "PROC_SPAWN" => "SPAWN",
        "PIPE_FLOW" => "PIPE",
        "BUFFER_FLOW" => "BUFFER",
        "SCM_RIGHTS" => "SCM",
        _ => "FLOW",
    };
    let label_y = (start.1 + end.1) / 2;
    if (label_y - start.1).abs() > 1 && (end.1 - label_y).abs() > 1 {
        text(
            buffer,
            area,
            scroll,
            (src.0 + dst.0) / 2 - label.len() as i32 / 2,
            label_y,
            label,
            color,
            label.len(),
        );
    }
}

fn draw_node(buffer: &mut Buffer, area: Rect, scroll: i32, x: i32, y: i32, node: &GraphNode) {
    let width = NODE_WIDTH.min(area.width.saturating_sub(2) as usize);
    if width < 6 {
        return;
    }
    let left = x - width as i32 / 2;
    let color = node_color(node);
    let horizontal = "─".repeat(width - 2);
    text(
        buffer,
        area,
        scroll,
        left,
        y,
        &format!("╭{horizontal}╮"),
        color,
        width,
    );
    text(
        buffer,
        area,
        scroll,
        left,
        y + 1,
        &format!("│{}│", " ".repeat(width - 2)),
        color,
        width,
    );
    text(
        buffer,
        area,
        scroll,
        left,
        y + 2,
        &format!("│{}│", " ".repeat(width - 2)),
        color,
        width,
    );
    text(
        buffer,
        area,
        scroll,
        left,
        y + 3,
        &format!("╰{horizontal}╯"),
        color,
        width,
    );
    text(
        buffer,
        area,
        scroll,
        left + 2,
        y,
        &node.id,
        color,
        width - 4,
    );
    cell(
        buffer,
        area,
        scroll,
        left + 2,
        y + 1,
        if is_risk(node) { "!" } else { "●" },
        color,
    );
    let op = node
        .label_fields
        .get("op")
        .map(String::as_str)
        .unwrap_or(&node.kind);
    text(buffer, area, scroll, left + 4, y + 1, op, TEXT, width - 5);
    let detail = node
        .label_fields
        .get("path_class")
        .map(String::as_str)
        .unwrap_or(&node.kind);
    text(
        buffer,
        area,
        scroll,
        left + 2,
        y + 2,
        detail,
        MUTED,
        width - 4,
    );
}

fn cell(buffer: &mut Buffer, area: Rect, scroll: i32, x: i32, y: i32, symbol: &str, color: Color) {
    let yy = y - scroll;
    if x < 0 || yy < 0 || x >= area.width as i32 || yy >= area.height as i32 {
        return;
    }
    if let Some(cell) = buffer.cell_mut((area.x + x as u16, area.y + yy as u16)) {
        cell.set_symbol(symbol).set_fg(color);
    }
}

fn text(
    buffer: &mut Buffer,
    area: Rect,
    scroll: i32,
    x: i32,
    y: i32,
    value: &str,
    color: Color,
    limit: usize,
) {
    for (offset, character) in value.chars().take(limit).enumerate() {
        let mut glyph = [0u8; 4];
        cell(
            buffer,
            area,
            scroll,
            x + offset as i32,
            y,
            character.encode_utf8(&mut glyph),
            color,
        );
    }
}

fn is_risk(node: &GraphNode) -> bool {
    if node.kind == "anchor" {
        return false;
    }
    let op = node
        .label_fields
        .get("op")
        .map(String::as_str)
        .unwrap_or("");
    let path_class = node
        .label_fields
        .get("path_class")
        .map(String::as_str)
        .unwrap_or("");
    let flags = node
        .label_fields
        .get("flags")
        .map(String::as_str)
        .unwrap_or("");
    ["DECOY", "SHELL", "SYSTEM_CONFIG", "NET_SEND", "NET_SOCKET"]
        .iter()
        .any(|term| op.contains(term) || path_class.contains(term))
        || op == "SHELL_EXEC"
        || (op == "FILE_WRITE" && flags == "CREATE_WRITE")
}

fn node_color(node: &GraphNode) -> Color {
    if node.kind == "anchor" {
        MUTED
    } else if is_risk(node) {
        ROSE
    } else if node
        .label_fields
        .get("path_class")
        .is_some_and(|v| v == "APP_ROOT")
    {
        GREEN
    } else {
        match node.label_fields.get("resource_kind").map(String::as_str) {
            Some("SOCKET") => TEAL,
            Some("PROCESS") => GREEN,
            Some("PIPE" | "MEMORY") => LAVENDER,
            Some("FILE") => BLUE,
            _ => TEXT,
        }
    }
}

fn edge_color(edge_type: &str) -> Color {
    match edge_type {
        "FD_FLOW" => BLUE,
        "PROCESS_FLOW" | "PROC_SPAWN" => GREEN,
        "PIPE_FLOW" => LAVENDER,
        "SCM_RIGHTS" => TEAL,
        "BUFFER_FLOW" => ROSE,
        _ => DIM,
    }
}
