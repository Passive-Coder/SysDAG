use std::fs;
use std::path::{Path, PathBuf};

use sysdag::pipeline::{classify_input, InputKind};
use sysdag::project::project_root_for_file;
use sysdag::sandbox::{stage_target, stage_target_with_entry};

struct TempProject(PathBuf);

impl TempProject {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sysdag-project-{name}-{}-{}",
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

#[test]
fn source_project_directory_is_not_treated_as_a_strace_directory() {
    let temp = TempProject::new("classification");
    fs::write(temp.path().join("main.py"), "import helper\n").unwrap();
    fs::write(temp.path().join("helper.py"), "VALUE = 1\n").unwrap();

    assert!(!matches!(
        classify_input(temp.path()).unwrap(),
        InputKind::Strace
    ));
}

#[test]
fn file_staging_includes_local_modules_and_data_with_relative_paths() {
    let temp = TempProject::new("dependencies");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("data")).unwrap();
    fs::write(project.join("main.py"), "import helper\n").unwrap();
    fs::write(project.join("helper.py"), "VALUE = 1\n").unwrap();
    fs::write(project.join("data/input.txt"), "sample\n").unwrap();
    let run = temp.path().join("run");
    fs::create_dir_all(run.join("target")).unwrap();

    let (entry, _) = stage_target(&run, &project.join("main.py")).unwrap();

    assert_eq!(entry, run.join("target/project/main.py"));
    assert_eq!(
        fs::read_to_string(run.join("target/project/helper.py")).unwrap(),
        "VALUE = 1\n"
    );
    assert_eq!(
        fs::read_to_string(run.join("target/project/data/input.txt")).unwrap(),
        "sample\n"
    );
}

#[test]
fn a_changed_local_dependency_changes_the_staged_project_identity() {
    let temp = TempProject::new("digest");
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("main.py"), "import helper\n").unwrap();
    fs::write(project.join("helper.py"), "VALUE = 1\n").unwrap();
    let first_run = temp.path().join("first-run");
    let second_run = temp.path().join("second-run");
    fs::create_dir_all(first_run.join("target")).unwrap();
    fs::create_dir_all(second_run.join("target")).unwrap();

    let (_, before) = stage_target(&first_run, &project.join("main.py")).unwrap();
    fs::write(project.join("helper.py"), "VALUE = 2\n").unwrap();
    let (_, after) = stage_target(&second_run, &project.join("main.py")).unwrap();

    assert_ne!(before, after);
}

#[test]
fn recorded_trace_directory_keeps_its_existing_classification() {
    let temp = TempProject::new("trace");
    fs::write(
        temp.path().join("trace.123"),
        "123 1.000000 openat(AT_FDCWD, \"/tmp/a\", O_RDONLY) = 3 <0.000001>\n",
    )
    .unwrap();
    assert!(matches!(
        classify_input(temp.path()).unwrap(),
        InputKind::Strace
    ));
}

#[test]
fn project_folder_selects_main_and_stages_nested_dependency() {
    let temp = TempProject::new("folder");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("lib")).unwrap();
    fs::write(project.join("main.py"), "from lib import helper\n").unwrap();
    fs::write(project.join("lib/helper.py"), "VALUE = 3\n").unwrap();
    let run = temp.path().join("run");
    fs::create_dir_all(run.join("target")).unwrap();

    let (entry, _) = stage_target(&run, &project).unwrap();

    assert_eq!(entry, run.join("target/project/main.py"));
    assert!(run.join("target/project/lib/helper.py").is_file());
}

#[test]
fn ambiguous_folder_requires_an_explicit_entrypoint() {
    let temp = TempProject::new("entry");
    fs::write(temp.path().join("first.py"), "print('first')\n").unwrap();
    fs::write(temp.path().join("second.py"), "print('second')\n").unwrap();
    let run = temp.path().join("run");
    fs::create_dir_all(&run).unwrap();

    let error = stage_target(&run, temp.path()).unwrap_err();
    assert!(error.to_string().contains("--entry"));
    let (entry, _) =
        stage_target_with_entry(&run, temp.path(), Some(Path::new("second.py"))).unwrap();
    assert_eq!(entry, run.join("target/project/second.py"));
}

#[test]
fn file_uses_nearest_project_marker_and_skips_generated_folders() {
    let temp = TempProject::new("nested");
    let outer = temp.path();
    fs::create_dir_all(outer.join(".git")).unwrap();
    let inner = outer.join("service");
    fs::create_dir_all(inner.join("src")).unwrap();
    fs::write(inner.join("pyproject.toml"), "[project]\nname='service'\n").unwrap();
    fs::write(inner.join("src/main.py"), "print('ok')\n").unwrap();
    fs::write(outer.join("unrelated.txt"), "other project\n").unwrap();
    fs::create_dir_all(inner.join("node_modules/lib")).unwrap();
    fs::write(inner.join("node_modules/lib/large.txt"), "generated\n").unwrap();
    let run = outer.join("run");
    fs::create_dir_all(&run).unwrap();

    assert_eq!(
        project_root_for_file(&inner.join("src/main.py")).unwrap(),
        inner.canonicalize().unwrap()
    );
    stage_target(&run, &inner.join("src/main.py")).unwrap();
    assert!(!run.join("target/project/unrelated.txt").exists());
    assert!(!run.join("target/project/node_modules").exists());
}
