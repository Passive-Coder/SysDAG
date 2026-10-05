use std::path::PathBuf;

use anyhow::{Context, Result};

const VIEWER_HTML: &str = include_str!("../../tools/viewer.html");
const VIEWER_JS: &str = include_str!("../../tools/d3.min.js");

pub fn open_graph_in_browser(graph: &crate::graph::GraphRecord) -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push(format!("sysdag-view-{}", std::process::id()));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let html_path = dir.join("sysdag-graph.html");
    let js_path = dir.join("d3.min.js");
    std::fs::write(&js_path, VIEWER_JS)?;
    let graph_script = format!(
        "<script>window.__SYSDAG_GRAPHS = {};</script>",
        javascript_safe_json(
            &serde_json::json!([{
                "name": graph.window.window_id,
                "data": graph,
            }])
            .to_string()
        )
    );
    let html = VIEWER_HTML.replace(
        r#"<script src="d3.min.js"></script>"#,
        &format!("{graph_script}\n<script src=\"d3.min.js\"></script>"),
    );
    std::fs::write(&html_path, html)?;

    open::that(&html_path)
        .map_err(|err| anyhow::anyhow!("open browser: {err}"))
        .with_context(|| format!("open {}", html_path.display()))?;
    Ok(html_path)
}

fn javascript_safe_json(json: &str) -> String {
    json.replace('<', "\\u003c")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_script_terminators() {
        assert_eq!(
            javascript_safe_json("{\"x\":\"</script>\"}"),
            "{\"x\":\"\\u003c/script>\"}"
        );
    }

    #[allow(dead_code)]
    fn viewer_assets_are_embedded() {
        assert!(VIEWER_HTML.contains("Load SysDAG graph files"));
        assert!(!VIEWER_JS.is_empty());
    }
}
