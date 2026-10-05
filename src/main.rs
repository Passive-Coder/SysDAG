use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use sysdag::config::Config;
use sysdag::help::{ABOUT, HELP};
use sysdag::pipeline::{analyze_path_opts, print_report, Mode};
use sysdag::sandbox::doctor;
use sysdag::tui::{self, LandingAction, Session};
use sysdag::visualizer::to_dot;

#[derive(Parser, Debug)]
#[command(
    name = "sysdag",
    version,
    about = ABOUT,
    after_help = HELP,
    help_template = "{after-help}",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Program, source file, or strace log (shortcut for `sysdag run <file>`)
    path: Option<PathBuf>,

    /// Arguments forwarded to the target inside the micro-VM
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    target_args: Vec<String>,

    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true)]
    json: bool,

    /// Skip the TUI and print a plain report
    #[arg(long, global = true)]
    plain: bool,

    #[arg(long, global = true)]
    workdir: Option<PathBuf>,

    /// Baseline identity (defaults to the file digest for programs, `strace-anonymous` for traces)
    #[arg(long, global = true)]
    id: Option<String>,

    /// Monitor with a baseline that fails compatibility checks (schema/pipeline/platform)
    #[arg(long, global = true)]
    allow_mismatch: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a target or analyze a trace (train if no baseline, else monitor)
    Run(RunArgs),
    /// Force baseline training from a clean execution or trace
    Train(RunArgs),
    /// Score a run against a frozen baseline
    Monitor(RunArgs),
    /// Check host prerequisites (Docker / guest image)
    Doctor,
    /// Print Graphviz DOT for a saved GraphRecord JSON
    Viz { graph: PathBuf },
    /// Dump score breakdown for a saved graph.json against a baseline
    Explain { baseline: PathBuf, graph: PathBuf },
    /// Verify a run directory's manifest and artifact checksums
    Verify { run_dir: PathBuf },
    /// Import a trace corpus into the reproducible experiments layout
    Dataset {
        #[command(subcommand)]
        command: DatasetCommand,
    },
    /// Train from clean train runs and freeze validation-calibrated thresholds
    Calibrate {
        #[arg(long)]
        dataset: String,
    },
    /// Evaluate a frozen baseline against a dataset's test runs
    Evaluate {
        #[arg(long)]
        dataset: String,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Run the immutable Phase 3 measurement gate for the strace prototype
    Measure {
        #[arg(long)]
        dataset: String,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Sweep representation, WL, and window ablations from a TOML grid
    Ablate {
        #[arg(long)]
        dataset: String,
        #[arg(long)]
        grid: PathBuf,
    },
    /// Evaluate the 1/2/3-gram sequence reference on the dataset split
    EvaluateNgram {
        #[arg(long)]
        dataset: String,
    },
    /// Consume JSONL or strace lines from a FIFO/file or tcp://host:port and score closed windows immediately
    MonitorLive {
        #[arg(long)]
        input: String,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long, default_value = "jsonl")]
        format: String,
        #[arg(long, default_value_t = 4096)]
        max_in_flight: usize,
    },
    /// Consume JSONL eBPF ring-buffer relay envelopes and score closed windows
    MonitorEbpf {
        #[arg(long)]
        input: String,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long, default_value_t = 4096)]
        max_in_flight: usize,
    },
    /// Attach the aya collector and write eBPF relay JSONL for a fixed duration
    CollectEbpf {
        #[arg(long)]
        object: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 30)]
        duration_secs: u64,
    },
}

#[derive(Subcommand, Debug)]
enum DatasetCommand {
    Import {
        dir: PathBuf,
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Program (.c/.py/.sh/ELF) or strace log
    path: PathBuf,
    /// Arguments forwarded to the target inside the micro-VM
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    target_args: Vec<String>,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("sysdag: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn collect_ebpf(
    object: &std::path::Path,
    output: &std::path::Path,
    duration_secs: u64,
) -> Result<i32> {
    use std::{
        fs::File,
        io::Write,
        time::{Duration, Instant},
    };
    sysdag::ebpf::linux_ebpf_available()?;
    let mut collector = sysdag::ebpf_native::AyaCollector::open(object)?;
    let mut out = File::create(output).with_context(|| format!("create {}", output.display()))?;
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    while Instant::now() < deadline {
        let (events, lost) = collector.drain()?;
        if lost > 0 {
            writeln!(
                out,
                "{}",
                serde_json::to_string(&sysdag::ebpf::EbpfEnvelope::Lost { count: lost })?
            )?;
        }
        for event in events {
            writeln!(
                out,
                "{}",
                serde_json::to_string(&sysdag::ebpf::EbpfEnvelope::Event { event })?
            )?;
        }
        out.flush()?;
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(0)
}

#[cfg(not(target_os = "linux"))]
fn collect_ebpf(
    _object: &std::path::Path,
    _output: &std::path::Path,
    _duration_secs: u64,
) -> Result<i32> {
    bail!("collect-ebpf requires Linux/WSL2")
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;
    let work = cli.workdir.unwrap_or_else(|| PathBuf::from(".sysdag"));
    let baseline_dir = work.join("baselines");

    match cli.command {
        Some(Command::Dataset {
            command: DatasetCommand::Import { dir, id },
        }) => {
            let manifest = sysdag::experiments::import_dataset(&dir, &work, id.as_deref())?;
            println!("imported dataset manifest {}", manifest.display());
            Ok(0)
        }
        Some(Command::Calibrate { dataset }) => {
            let baseline = sysdag::experiments::calibrate(&work, &dataset, &cfg)?;
            println!("calibrated baseline {}", baseline.display());
            Ok(0)
        }
        Some(Command::Evaluate { dataset, baseline }) => {
            let report = sysdag::experiments::evaluate(&work, &dataset, &baseline, &cfg)?;
            println!("wrote evaluation {}", report.display());
            Ok(0)
        }
        Some(Command::Measure { dataset, baseline }) => {
            let result = sysdag::experiments::measure(&work, &dataset, &baseline, &cfg)?;
            println!("wrote immutable measurement {}", result.display());
            Ok(0)
        }
        Some(Command::Ablate { dataset, grid }) => {
            let result = sysdag::experiments::ablate(&work, &dataset, &grid, &cfg)?;
            println!("wrote ablation {}", result.display());
            Ok(0)
        }
        Some(Command::EvaluateNgram { dataset }) => {
            let result = sysdag::experiments::evaluate_ngram(&work, &dataset, &cfg)?;
            println!("wrote n-gram evaluation {}", result.display());
            Ok(0)
        }
        Some(Command::MonitorLive {
            input,
            baseline,
            format,
            max_in_flight,
        }) => {
            use std::io::{BufRead, BufReader};
            use std::net::TcpStream;
            use std::time::Instant;
            let baseline = sysdag::detector::load_baseline(&baseline)?;
            let reader: Box<dyn BufRead> = if let Some(addr) = input.strip_prefix("tcp://") {
                Box::new(BufReader::new(TcpStream::connect(addr)?))
            } else {
                Box::new(BufReader::new(std::fs::File::open(&input)?))
            };
            let mut builder = sysdag::streaming::WindowBuilder::new(
                cfg.clone(),
                "live",
                &baseline.target_sha256,
                max_in_flight,
            );
            let mut strace = sysdag::tracer::LiveStraceParser::new(cfg.clone());
            for (i, line) in reader.lines().enumerate() {
                let line = line?;
                let event = match format.as_str() {
                    "jsonl" => {
                        if line.trim().is_empty() {
                            continue;
                        } else {
                            serde_json::from_str(&line)
                                .map_err(|error| anyhow::anyhow!("{input}:{}: {error}", i + 1))?
                        }
                    }
                    "strace" => match strace.push(&line) {
                        Some(event) => event,
                        None => continue,
                    },
                    _ => bail!("--format must be jsonl or strace"),
                };
                let started = Instant::now();
                if let Some(graph) = builder.push(event) {
                    let decision = sysdag::detector::score(&graph, &baseline, &cfg);
                    println!(
                        "{}",
                        serde_json::to_string(
                            &serde_json::json!({"decision": decision, "processing_latency_ns": started.elapsed().as_nanos(), "evicted_events": builder.evicted()})
                        )?
                    );
                }
            }
            Ok(0)
        }
        Some(Command::MonitorEbpf {
            input,
            baseline,
            max_in_flight,
        }) => {
            use std::io::{BufRead, BufReader};
            use std::net::TcpStream;
            use std::time::Instant;
            sysdag::ebpf::linux_ebpf_available()?;
            let baseline = sysdag::detector::load_baseline(&baseline)?;
            let reader: Box<dyn BufRead> = if let Some(addr) = input.strip_prefix("tcp://") {
                Box::new(BufReader::new(TcpStream::connect(addr)?))
            } else {
                Box::new(BufReader::new(std::fs::File::open(&input)?))
            };
            let mut builder = sysdag::streaming::WindowBuilder::new(
                cfg.clone(),
                "ebpf",
                &baseline.target_sha256,
                max_in_flight,
            );
            for (i, line) in reader.lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                match sysdag::ebpf::EbpfEnvelope::parse_jsonl(&line)
                    .map_err(|error| anyhow::anyhow!("{input}:{}: {error}", i + 1))?
                {
                    sysdag::ebpf::EbpfEnvelope::Lost { count } => {
                        builder.record_capture_loss(count)
                    }
                    sysdag::ebpf::EbpfEnvelope::Event { event } => {
                        let started = Instant::now();
                        if let Some(graph) = builder.push(event) {
                            let decision = sysdag::detector::score(&graph, &baseline, &cfg);
                            println!(
                                "{}",
                                serde_json::to_string(
                                    &serde_json::json!({"decision": decision, "processing_latency_ns": started.elapsed().as_nanos(), "capture_loss": builder.evicted()})
                                )?
                            );
                        }
                    }
                }
            }
            Ok(0)
        }
        Some(Command::CollectEbpf {
            object,
            output,
            duration_secs,
        }) => collect_ebpf(&object, &output, duration_secs),
        Some(Command::Verify { run_dir }) => {
            let m = sysdag::load_run_manifest(&run_dir)?;
            m.verify_against(&run_dir)?;
            println!(
                "ok: manifest {} ({} mode, {} events, {} artifacts) verified",
                m.run_id,
                m.mode,
                m.event_count,
                m.artifact_checksums.len()
            );
            Ok(0)
        }
        Some(Command::Doctor) => {
            doctor()?;
            Ok(0)
        }
        Some(Command::Viz { graph }) => {
            let text = std::fs::read_to_string(&graph)?;
            let g: sysdag::graph::GraphRecord = serde_json::from_str(&text)?;
            print!("{}", to_dot(&g));
            Ok(0)
        }
        Some(Command::Explain { baseline, graph }) => {
            use sysdag::detector::load_baseline;
            use sysdag::detector::score_breakdown;
            use sysdag::features::encode;
            let b = load_baseline(&baseline)?;
            let text = std::fs::read_to_string(&graph)?;
            let g: sysdag::graph::GraphRecord = serde_json::from_str(&text)?;
            let enc = encode(g, &cfg);
            let breakdown = score_breakdown(&enc, &b, &cfg);
            println!(
                "alpha={:.4} beta={:.4} gamma={:.4} delta={:.4} total={:.4}",
                breakdown.alpha, breakdown.beta, breakdown.gamma, breakdown.delta, breakdown.total
            );
            Ok(0)
        }
        Some(Command::Train(args)) => dispatch(
            &args.path,
            Mode::Train,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
            cli.allow_mismatch,
        ),
        Some(Command::Monitor(args)) => dispatch(
            &args.path,
            Mode::Monitor,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
            cli.allow_mismatch,
        ),
        Some(Command::Run(args)) => dispatch(
            &args.path,
            Mode::Auto,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
            cli.allow_mismatch,
        ),
        None => {
            let Some(path) = cli.path else {
                if tui::should_open(cli.plain, cli.json) {
                    return match tui::run_landing()? {
                        LandingAction::Quit => Ok(0),
                        LandingAction::Run { path, args } => dispatch(
                            &path,
                            Mode::Auto,
                            &cfg,
                            &work,
                            &baseline_dir,
                            &args,
                            cli.json,
                            cli.plain,
                            cli.id.as_deref(),
                            cli.allow_mismatch,
                        ),
                    };
                }
                print!("{HELP}");
                return Ok(0);
            };
            dispatch(
                &path,
                Mode::Auto,
                &cfg,
                &work,
                &baseline_dir,
                &cli.target_args,
                cli.json,
                cli.plain,
                cli.id.as_deref(),
                cli.allow_mismatch,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    path: &std::path::Path,
    mode: Mode,
    cfg: &Config,
    work: &std::path::Path,
    baseline_dir: &std::path::Path,
    target_args: &[String],
    json: bool,
    plain: bool,
    identity: Option<&str>,
    allow_mismatch: bool,
) -> Result<i32> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    if tui::should_open(plain, json) {
        return tui::run(Session {
            path: path.to_path_buf(),
            mode,
            cfg: cfg.clone(),
            work: work.to_path_buf(),
            baseline_dir: baseline_dir.to_path_buf(),
            target_args: target_args.to_vec(),
            identity: identity.map(str::to_string),
            allow_mismatch,
        });
    }
    let report = analyze_path_opts(
        path,
        mode,
        cfg,
        work,
        baseline_dir,
        target_args,
        true,
        identity,
        sysdag::pipeline::AnalyzeOpts { allow_mismatch },
    )?;
    print_report(&report, json)
}
