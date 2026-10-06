//! The `--help` listing. Keep this the source of truth for what the tool does.

pub const ABOUT: &str = "Show the causal shape of a process";

pub const HELP: &str = "\
sysdag — show how a process used the kernel

USAGE
  sysdag                       open the landing app (TTY)
  sysdag <path> [args]         run, then show the graph
  sysdag train <path>          write a clean baseline
  sysdag monitor <path>        score against a baseline
  sysdag doctor                check docker / guest
  sysdag viz <graph.json>      print Graphviz

OPTIONS
  --help          this list
  --version       version
  --plain         text instead of the viewer
  --json          machine-readable report
  --config PATH   toml config
  --workdir DIR   artifacts (default .sysdag)
  --id NAME       baseline identity
  --entry PATH    entrypoint within a project folder

<path> is a project folder, .c / .py / .sh program, Linux ELF, or strace log.
First run trains. Later runs of the same project monitor.

On the landing
  type a path + enter   run
  ?                     commands
  q                     quit

In the viewer
  tab  1-4   overview / graph / events / inspect
  j k        move
  [ ]        window
  v          open current graph in browser
  q          quit
";
