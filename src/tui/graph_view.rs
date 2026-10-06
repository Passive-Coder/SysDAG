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
const ROW_SPACING: i32 = 12;

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
    let mut routes: BTreeMap<(usize, &str), Vec<usize>> = BTreeMap::new();
    for edge in &edges {
        routes
            .entry((ids[edge.src.as_str()], edge.edge_type.as_str()))
            .or_default()
            .push(ids[edge.dst.as_str()]);
    }
    for ((source, edge_type), targets) in routes {
        let mut destinations: Vec<_> = targets.into_iter().map(|index| positions[index]).collect();
        destinations.sort_unstable();
        destinations.dedup();
        draw_route(
            buffer,
            canvas,
            app.scroll as i32,
            positions[source],
            &destinations,
            edge_type,
        );
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
    let mut parents = vec![Vec::new(); nodes.len()];
    let mut indegree = vec![0usize; nodes.len()];
    for edge in edges {
        let src = ids[edge.src.as_str()];
        let dst = ids[edge.dst.as_str()];
        children[src].push(dst);
        parents[dst].push(src);
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
    for (index, level) in levels.iter().enumerate() {
        groups.entry(level.unwrap_or(0)).or_default().push(index);
    }
    let card_width = NODE_WIDTH.min(width.saturating_sub(2)).max(1);
    let columns = (width / (card_width + 4)).max(1);
    let mut positions = vec![(0, 0); nodes.len()];
    let mut y = 2;
    for (level, group) in &mut groups {
        // Place siblings near their parents, like the browser hierarchy. This
        // keeps separate fan-outs from crossing in the common case.
        group.sort_by_key(|&index| {
            let parent_x: Vec<i32> = parents[index]
                .iter()
                .filter(|&&parent| levels[parent].unwrap_or(0) < *level)
                .map(|&parent| positions[parent].0)
                .collect();
            if parent_x.is_empty() {
                width as i32 / 2
            } else {
                parent_x.iter().sum::<i32>() / parent_x.len() as i32
            }
        });
        for row in group.chunks(columns) {
            for (slot, &index) in row.iter().enumerate() {
                let x = ((slot + 1) * width / (row.len() + 1)) as i32;
                positions[index] = (x, y);
            }
            y += ROW_SPACING;
        }
        y += 4;
    }
    positions
}

fn draw_route(
    buffer: &mut Buffer,
    area: Rect,
    scroll: i32,
    src: (i32, i32),
    destinations: &[(i32, i32)],
    edge_type: &str,
) {
    if destinations.is_empty() {
        return;
    }
    let color = edge_color(edge_type);
    let start_y = src.1 + 4;
    let nearest = destinations
        .iter()
        .map(|(_, y)| *y)
        .min()
        .unwrap_or(src.1 + 12);
    let bus_y = if nearest > start_y + 4 {
        (start_y + nearest - 1) / 2
    } else {
        start_y + 2
    };
    for y in start_y..bus_y {
        cell(buffer, area, scroll, src.0, y, "│", color);
    }
    let left = destinations
        .iter()
        .map(|(x, _)| *x)
        .min()
        .unwrap_or(src.0)
        .min(src.0);
    let right = destinations
        .iter()
        .map(|(x, _)| *x)
        .max()
        .unwrap_or(src.0)
        .max(src.0);
    for x in left..=right {
        cell(buffer, area, scroll, x, bus_y, "─", color);
    }
    cell(buffer, area, scroll, src.0, bus_y, "┴", color);
    for &(x, y) in destinations {
        let end_y = y - 1;
        if end_y > bus_y {
            for row in bus_y + 1..end_y {
                cell(buffer, area, scroll, x, row, "│", color);
            }
            cell(buffer, area, scroll, x, end_y, "▼", color);
        } else {
            for row in end_y + 1..bus_y {
                cell(buffer, area, scroll, x, row, "│", color);
            }
            cell(buffer, area, scroll, x, end_y, "▲", color);
        }
        if x != src.0 {
            cell(buffer, area, scroll, x, bus_y, "┬", color);
        }
    }
    let label = match edge_type {
        "FD_FLOW" => "FD",
        "PROCESS_FLOW" => "PROCESS",
        "PROC_SPAWN" => "SPAWN",
        "PIPE_FLOW" => "PIPE",
        "BUFFER_FLOW" => "BUFFER",
        "SCM_RIGHTS" => "SCM",
        _ => "FLOW",
    };
    if bus_y - start_y > 2 {
        text(
            buffer,
            area,
            scroll,
            src.0 + 2,
            bus_y - 1,
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
