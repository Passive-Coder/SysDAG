use std::fs;
use std::path::{Path, PathBuf};

use sysdag::config::Config;
use sysdag::sandbox::{docker_available, prepare_run_dir, run_in_microvm, stage_target};

struct TempProject(PathBuf);

impl TempProject {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sysdag-runtime-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_project(project: &Path, run: &Path) -> anyhow::Result<()> {
    let run_dir = prepare_run_dir(run, "case")?;
    let (entry, _) = stage_target(&run_dir, project)?;
    let guest_rel = entry.strip_prefix(&run_dir)?.to_string_lossy().to_string();
    run_in_microvm(&Config::default(), &run_dir, &guest_rel, &[])?;
    Ok(())
}

#[test]
fn python_entrypoint_can_import_local_module_and_read_project_data() {
    if !docker_available() {
        return;
    }
    let temp = TempProject::new("python");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("data")).unwrap();
    fs::write(project.join("main.py"), "import helper\nhelper.run()\n").unwrap();
    fs::write(
        project.join("helper.py"),
        "def run():\n    assert open('data/input.txt').read().strip() == 'ready'\n",
    )
    .unwrap();
    fs::write(project.join("data/input.txt"), "ready\n").unwrap();

    run_project(&project, &temp.path().join("runs")).unwrap();
}

#[test]
fn c_entrypoint_links_local_helper_source_and_header() {
    if !docker_available() {
        return;
    }
    let temp = TempProject::new("c");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("include")).unwrap();
    fs::write(
        project.join("main.c"),
        "#include \"helper.h\"\nint main(void) { return helper() == 7 ? 0 : 1; }\n",
    )
    .unwrap();
    fs::write(project.join("include/helper.h"), "int helper(void);\n").unwrap();
    fs::write(project.join("helper.c"), "int helper(void) { return 7; }\n").unwrap();

    run_project(&project, &temp.path().join("runs")).unwrap();
}
