//! State-machine strace parser. A single regex is not sufficient.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::event::{CaptureInfo, EventArgs, Iovec, ParseStats, ProcessRef, SyscallRef, TraceEvent};
use crate::labels::{build_labels, is_fd_allocator, is_tracked};

/// Path redactor for privacy: maps real paths to stable tokens or hashes.
#[derive(Debug, Default)]
struct PathRedactor {
    mapping: HashMap<String, String>,
    counter: usize,
}

impl PathRedactor {
    fn new() -> Self {
        Self::default()
    }

    fn redact(&mut self, path: &str, use_hash: bool) -> String {
        if let Some(existing) = self.mapping.get(path) {
            return existing.clone();
        }
        let token = if use_hash {
            let mut hasher = Sha256::new();
            hasher.update(path.as_bytes());
            format!("H{:x}", hasher.finalize())[..16].to_string()
        } else {
            let token = format!("F{}", self.counter + 1);
            self.counter += 1;
            token
        };
        self.mapping.insert(path.to_string(), token.clone());
        token
    }

    fn exported_mapping(&self) -> BTreeMap<String, String> {
        // The on-disk local map is deliberately token -> plaintext.  This keeps
        // exported event/graph artifacts usable without putting plaintext in
        // them; callers must write it only inside the run directory.
        self.mapping
            .iter()
            .map(|(plain, token)| (token.clone(), plain.clone()))
            .collect()
    }
}

#[derive(Debug, Clone)]
struct Unfinished {
    enter_ns: u64,
    args_prefix: String,
    raw: String,
}

#[derive(Debug)]
struct FileParser {
    pid_hint: Option<i32>,
    unfinished: HashMap<String, Vec<Unfinished>>,
    stats: ParseStats,
}

#[derive(Debug)]
struct RawEvent {
    pid: i32,
    tid: i32,
    enter_ns: u64,
    exit_ns: u64,
    name: String,
    args: EventArgs,
    ret: Option<i64>,
    errno: Option<String>,
    raw: String,
}

pub fn parse_strace_path(path: &Path, cfg: &Config) -> Result<(Vec<TraceEvent>, ParseStats)> {
    let (events, stats, _) = parse_strace_path_with_privacy_map(path, cfg)?;
    Ok((events, stats))
}

/// Stateful single-line decoder for FIFO/socket strace streams.  Unlike the
/// batch parser it preserves unfinished/resumed call state across `push` calls.
pub struct LiveStraceParser {
    parser: FileParser,
    cfg: Config,
    redactor: PathRedactor,
    seq: u64,
}

impl LiveStraceParser {
    pub fn new(cfg: Config) -> Self {
        Self {
            parser: FileParser {
                pid_hint: None,
                unfinished: HashMap::new(),
                stats: ParseStats::default(),
            },
            cfg,
            redactor: PathRedactor::new(),
            seq: 0,
        }
    }

    pub fn push(&mut self, line: &str) -> Option<TraceEvent> {
        self.parser.stats.lines += 1;
        let raw = self.parser.push_line(line)?;
        let mut events = materialize(
            vec![raw],
            &self.cfg,
            &mut self.parser.stats,
            &mut self.redactor,
        );
        let mut event = events.pop()?;
        self.seq += 1;
        event.seq = self.seq;
        Some(event)
    }

    pub fn stats(&self) -> &ParseStats {
        &self.parser.stats
    }
}

/// Parse a trace and return the private token-to-path map separately from the
/// event stream.  The caller is responsible for storing this map locally only.
pub fn parse_strace_path_with_privacy_map(
    path: &Path,
    cfg: &Config,
) -> Result<(Vec<TraceEvent>, ParseStats, BTreeMap<String, String>)> {
    let mut redactor = PathRedactor::new();
    if path.is_dir() {
        let mut files: Vec<_> = fs::read_dir(path)
            .with_context(|| format!("read trace dir {}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        let mut all = Vec::new();
        let mut stats = ParseStats::default();
        for f in files {
            let (ev, st) = parse_strace_file(&f, cfg, &mut redactor)?;
            merge_stats(&mut stats, &st);
            all.extend(ev);
        }
        finalize_events(&mut all);
        return Ok((all, stats, redactor.exported_mapping()));
    }
    let (mut events, stats) = parse_strace_file(path, cfg, &mut redactor)?;
    finalize_events(&mut events);
    Ok((events, stats, redactor.exported_mapping()))
}

fn parse_strace_file(
    path: &Path,
    cfg: &Config,
    path_redactor: &mut PathRedactor,
) -> Result<(Vec<TraceEvent>, ParseStats)> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let pid_hint = pid_from_filename(path);
    let mut parser = FileParser {
        pid_hint,
        unfinished: HashMap::new(),
        stats: ParseStats::default(),
    };
    let mut raw_events = Vec::new();
    for line in text.lines() {
        parser.stats.lines += 1;
        if let Some(ev) = parser.push_line(line) {
            raw_events.push(ev);
        }
    }
    // Unfinished calls that were never resumed are lost events (Phase 1.3).
    let never_resumed: u64 = parser.unfinished.values().map(|q| q.len() as u64).sum();
    parser.stats.lost_events_estimate += never_resumed;
    let mut stats = parser.stats;
    let events = materialize(raw_events, cfg, &mut stats, path_redactor);
    Ok((events, stats))
}

fn pid_from_filename(path: &Path) -> Option<i32> {
    let name = path.file_name()?.to_str()?;
    name.rsplit('.').next()?.parse().ok()
}

impl FileParser {
    fn push_line(&mut self, line: &str) -> Option<RawEvent> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (pid_inline, rest) = strip_pid_prefix(trimmed);
        let Some((ts, body)) = split_timestamp(rest) else {
            self.stats.rejected += 1;
            return None;
        };
        if body.starts_with("--- ") {
            self.stats.signals += 1;
            return None;
        }
        if body.starts_with("+++ ") {
            self.stats.exits += 1;
            return None;
        }
        let pid = pid_inline.or(self.pid_hint).unwrap_or(0);
        if let Some(name) = unfinished_name(body) {
            self.stats.unfinished += 1;
            let args_prefix = body
                .split_once('(')
                .map(|(_, r)| r.replace(" <unfinished ...>", ""))
                .unwrap_or_default();
            self.unfinished.entry(name).or_default().push(Unfinished {
                enter_ns: ts,
                args_prefix,
                raw: trimmed.to_string(),
            });
            return None;
        }
        if let Some((name, resumed)) = resumed_parts(body) {
            let start = self.unfinished.get_mut(&name).and_then(|q| q.pop());
            let Some(start) = start else {
                self.stats.rejected += 1;
                return None;
            };
            let merged = format!("{}({})", name, join_unfinished(&start.args_prefix, resumed));
            return self.finish(
                pid,
                start.enter_ns,
                ts,
                &merged,
                &format!("{}\n{trimmed}", start.raw),
            );
        }
        self.finish(pid, ts, ts, body, trimmed)
    }

    fn finish(
        &mut self,
        pid: i32,
        enter_ns: u64,
        exit_ns: u64,
        body: &str,
        raw: &str,
    ) -> Option<RawEvent> {
        match parse_completed(body) {
            Some((name, args, ret, errno)) => Some(RawEvent {
                pid,
                tid: pid,
                enter_ns,
                exit_ns,
                name,
                args,
                ret,
                errno,
                raw: raw.to_string(),
            }),
            None => {
                self.stats.rejected += 1;
                None
            }
        }
    }
}

fn materialize(
    raw: Vec<RawEvent>,
    cfg: &Config,
    stats: &mut ParseStats,
    path_redactor: &mut PathRedactor,
) -> Vec<TraceEvent> {
    raw.into_iter()
        .filter(|r| {
            let tracked = is_tracked(&r.name, &cfg.syscall_classes);
            if !tracked {
                stats.unknown_syscalls += 1;
            }
            tracked
        })
        .map(|r| {
            // Redact paths in args
            let mut args = r.args;
            if cfg.privacy.is_redact_enabled() {
                if let Some(path) = &args.path {
                    args.path = Some(path_redactor.redact(path, cfg.privacy.use_hash()));
                }
                if let Some(fd_path) = &args.fd_path {
                    args.fd_path = Some(path_redactor.redact(fd_path, cfg.privacy.use_hash()));
                }
            }
            let labels = build_labels(
                &r.name,
                args.path.as_deref().unwrap_or(""),
                args.flags.as_deref().unwrap_or(""),
                args.fd_path.as_deref().unwrap_or(""),
                args.sock_info.as_deref().unwrap_or(""),
                r.ret,
                r.errno.as_deref(),
                args.count
                    .filter(|_| r.errno.is_none())
                    .or(r.ret.filter(|v| *v >= 0)),
                &cfg.labels.app_root,
            );
            TraceEvent::new(
                ProcessRef {
                    pid: r.pid,
                    tid: r.tid,
                    start_ns: 0,
                    image_gen: 0,
                    comm: String::new(),
                },
                0,
                r.enter_ns,
                r.exit_ns,
                SyscallRef {
                    nr: -1,
                    name: r.name,
                    arch: "linux".into(),
                },
                args,
                r.ret,
                r.errno,
                labels,
                CaptureInfo {
                    source: "strace".into(),
                    truncated: false,
                    raw_line: if cfg.privacy.persist_raw_lines {
                        r.raw
                    } else {
                        String::new()
                    },
                    lost: false,
                },
            )
        })
        .collect()
}

fn finalize_events(events: &mut [TraceEvent]) {
    events.sort_by(|a, b| {
        (a.enter_ns, a.process.pid, a.syscall.name.as_str()).cmp(&(
            b.enter_ns,
            b.process.pid,
            b.syscall.name.as_str(),
        ))
    });
    for (i, ev) in events.iter_mut().enumerate() {
        ev.seq = (i as u64) + 1;
    }
}

fn merge_stats(dst: &mut ParseStats, src: &ParseStats) {
    dst.lines += src.lines;
    dst.events += src.events;
    dst.rejected += src.rejected;
    dst.signals += src.signals;
    dst.exits += src.exits;
    dst.unfinished += src.unfinished;
    dst.unknown_syscalls += src.unknown_syscalls;
    dst.malformed_records += src.malformed_records;
    dst.lost_events_estimate += src.lost_events_estimate;
}

fn strip_pid_prefix(line: &str) -> (Option<i32>, &str) {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("[pid ") {
        if let Some((num, after)) = rest.split_once(']') {
            return (num.trim().parse().ok(), after.trim_start());
        }
    }
    (None, line)
}

fn split_timestamp(line: &str) -> Option<(u64, &str)> {
    let (first, rest) = line.split_once(' ')?;
    if !first.chars().next()?.is_ascii_digit() || !first.contains('.') {
        return None;
    }
    let (sec, frac) = first.split_once('.')?;
    let sec: u64 = sec.parse().ok()?;
    let mut micros = frac.to_string();
    while micros.len() < 9 {
        micros.push('0');
    }
    micros.truncate(9);
    let ns_frac: u64 = micros.parse().ok()?;
    Some((sec.saturating_mul(1_000_000_000) + ns_frac, rest))
}

fn unfinished_name(body: &str) -> Option<String> {
    if !body.contains("<unfinished ...>") {
        return None;
    }
    let name = body.split('(').next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(normalize_name(name))
}

fn resumed_parts(body: &str) -> Option<(String, &str)> {
    let rest = body.strip_prefix("<... ")?;
    let (name, after) = rest.split_once(" resumed>")?;
    Some((normalize_name(name.trim()), after.trim_start()))
}

fn join_unfinished(prefix: &str, resumed: &str) -> String {
    let p = prefix.trim().trim_end_matches(',');
    let r = resumed.trim().trim_start_matches(',');
    if p.is_empty() {
        r.to_string()
    } else if r.is_empty() {
        p.to_string()
    } else {
        format!("{p}, {r}")
    }
}

fn normalize_name(name: &str) -> String {
    let base = name.split('@').next().unwrap_or(name).trim();
    base.to_string()
}

fn parse_completed(body: &str) -> Option<(String, EventArgs, Option<i64>, Option<String>)> {
    let body = body.trim();
    let name_end = body.find('(')?;
    let name = normalize_name(&body[..name_end]);
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let after_name = &body[name_end + 1..];
    let (args_src, tail) = split_args_and_tail(after_name)?;
    let (ret, errno) = parse_return(tail);
    let mut args = interpret_args(&name, &args_src);
    let is_dup = matches!(name.as_str(), "dup" | "dup2" | "dup3")
        || (name == "fcntl"
            && args
                .flags
                .as_deref()
                .map(|f| f.contains("DUP"))
                .unwrap_or(false));
    if args.fd.is_none() && is_fd_allocator(&name) && !is_dup {
        if let Some(r) = ret.filter(|v| *v >= 0) {
            args.fd = Some(r as i32);
        }
    }
    if is_dup {
        if let Some(r) = ret.filter(|v| *v >= 0) {
            args.newfd = Some(r as i32);
        }
    }
    if matches!(name.as_str(), "clone" | "clone3" | "fork" | "vfork") {
        if let Some(r) = ret.filter(|v| *v > 0) {
            args.child_pid = Some(r as i32);
        }
    }
    Some((name, args, ret, errno))
}

fn split_args_and_tail(s: &str) -> Option<(String, &str)> {
    let mut depth = 1i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in s.char_indices() {
        if in_str {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((s[..i].to_string(), s[i + 1..].trim_start()));
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_return(tail: &str) -> (Option<i64>, Option<String>) {
    let t = tail.trim();
    let t = t.strip_prefix('=').unwrap_or(t).trim();
    if t.is_empty() || t.starts_with('?') {
        return (None, None);
    }
    let t = strip_duration(t);
    let token = t.split_whitespace().next().unwrap_or("");
    let token = token.split('<').next().unwrap_or(token);
    let ret = parse_int_token(token);
    let errno = t
        .split_whitespace()
        .nth(1)
        .filter(|s| {
            s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
        .map(|s| s.to_string());
    (ret, errno)
}

fn strip_duration(s: &str) -> &str {
    if let Some(idx) = s.rfind('<') {
        if s.trim_end().ends_with('>') {
            return s[..idx].trim_end();
        }
    }
    s
}

fn parse_int_token(tok: &str) -> Option<i64> {
    let tok = tok.trim();
    if tok.is_empty() || tok == "?" {
        return None;
    }
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    tok.parse().ok()
}

fn interpret_args(name: &str, raw: &str) -> EventArgs {
    let parts = split_top_args(raw);
    let mut args = EventArgs::default();
    match name {
        "open" | "creat" => {
            args.path = first_path(&parts);
            args.flags = parts.get(1).cloned();
        }
        "openat" | "openat2" | "newfstatat" | "faccessat" | "faccessat2" | "unlinkat"
        | "mkdirat" | "execveat" => {
            args.dirfd = parts.first().and_then(|s| parse_fd_number(s));
            args.path = first_path(&parts);
            args.flags = parts.get(2).cloned();
        }
        "execve" | "stat" | "lstat" | "access" | "unlink" | "chdir" | "chmod" | "readlink" => {
            args.path = first_path(&parts);
        }
        "read" | "write" | "pread64" | "pwrite64" | "sendto" | "recvfrom" | "send" | "recv"
        | "sendmsg" | "recvmsg" => {
            fill_fd(&mut args, parts.first());
            if let Some(buf) = parts.get(1) {
                args.buffer_addr = parse_hex_addr(buf);
                if buf.starts_with('"') {
                    args.buffer = Some("0xREDACTED".into());
                }
            }
            args.count = parts
                .get(2)
                .or(parts.last())
                .and_then(|s| parse_int_token(s.trim_end_matches(',')));
            if name == "recvmsg" {
                args.received_fds = parse_scm_rights(raw);
            }
        }
        "readv" | "writev" | "preadv" | "pwritev" => {
            fill_fd(&mut args, parts.first());
            args.iovecs = parse_iovecs(parts.get(1).map(String::as_str).unwrap_or(""));
            if let Some(first) = args.iovecs.first() {
                args.buffer_addr = Some(first.addr);
                args.count = Some(first.len as i64);
            }
        }
        "close" | "lseek" | "fstat" | "fsync" | "connect" | "bind" | "listen" | "accept"
        | "accept4" | "shutdown" => {
            fill_fd(&mut args, parts.first());
        }
        "dup" => fill_fd(&mut args, parts.first()),
        "dup2" | "dup3" => {
            fill_fd(&mut args, parts.first());
            args.newfd = parts.get(1).and_then(|s| parse_fd_number(s));
        }
        "fcntl" => {
            fill_fd(&mut args, parts.first());
            args.flags = parts.get(1).cloned();
        }
        "pipe" | "pipe2" => {
            args.pipe_fds = parse_pipe_fds(raw);
        }
        "clone" | "clone3" => {
            args.flags = parts.first().cloned();
        }
        "socket" => {
            args.flags = parts.get(1).cloned();
        }
        _ => {
            fill_fd(&mut args, parts.first());
            if args.path.is_none() {
                args.path = first_path(&parts);
            }
        }
    }
    args
}

fn fill_fd(args: &mut EventArgs, tok: Option<&String>) {
    if let Some(tok) = tok {
        args.fd = parse_fd_number(tok);
        if let Some(dec) = decode_fd_annotation(tok) {
            if dec.contains("TCP") || dec.contains("UDP") || dec.contains("socket") {
                args.sock_info = Some(dec);
            } else {
                args.fd_path = Some(dec);
            }
        }
    }
}

fn split_top_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '(' | '{' | '[' => {
                depth += 1;
                cur.push(c);
            }
            ')' | '}' | ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                let t = cur.trim().to_string();
                if !t.is_empty() {
                    out.push(t);
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        out.push(t);
    }
    out
}

fn first_path(parts: &[String]) -> Option<String> {
    for p in parts {
        if let Some(s) = unquote(p) {
            if s.starts_with('/') || s.starts_with('.') || s.contains('/') {
                return Some(s);
            }
        }
    }
    None
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Some(unescape(&s[1..s.len() - 1]));
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_fd_number(tok: &str) -> Option<i32> {
    let tok = tok.trim();
    if tok == "AT_FDCWD" {
        return Some(-100);
    }
    let num = tok.split('<').next().unwrap_or(tok);
    num.parse().ok()
}

fn decode_fd_annotation(tok: &str) -> Option<String> {
    let start = tok.find('<')?;
    let end = tok.rfind('>')?;
    if end <= start + 1 {
        return None;
    }
    Some(tok[start + 1..end].to_string())
}

fn parse_hex_addr(tok: &str) -> Option<u64> {
    let tok = tok.trim();
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

fn parse_pipe_fds(raw: &str) -> Option<(i32, i32)> {
    let inner = raw.find('[')?;
    let rest = &raw[inner + 1..];
    let end = rest.find(']')?;
    let parts = split_top_args(&rest[..end]);
    if parts.len() >= 2 {
        return Some((parse_fd_number(&parts[0])?, parse_fd_number(&parts[1])?));
    }
    None
}

pub fn looks_like_strace(text: &str) -> bool {
    text.lines()
        .take(20)
        .filter(|l| !l.trim().is_empty())
        .any(|l| split_timestamp(strip_pid_prefix(l.trim()).1).is_some())
}

pub const STRACE_FILTER: &str = "%file,%network,%desc,%process";

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn parses_openat_read_close() {
        let body = r#"openat(AT_FDCWD, "/app/www/index.html", O_RDONLY) = 3</app/www/index.html> <0.000010>"#;
        let (name, args, ret, errno) = parse_completed(body).unwrap();
        assert_eq!(name, "openat");
        assert_eq!(args.path.as_deref(), Some("/app/www/index.html"));
        assert_eq!(args.fd, Some(3));
        assert_eq!(ret, Some(3));
        assert!(errno.is_none());
    }

    #[test]
    fn parses_failed_open() {
        let body = r#"openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000008>"#;
        let (_, _, ret, errno) = parse_completed(body).unwrap();
        assert_eq!(ret, Some(-1));
        assert_eq!(errno.as_deref(), Some("ENOENT"));
    }

    #[test]
    fn unfinished_and_resumed() {
        let mut p = FileParser {
            pid_hint: Some(9),
            unfinished: HashMap::new(),
            stats: ParseStats::default(),
        };
        assert!(p
            .push_line("1000.000001 read(3,  <unfinished ...>")
            .is_none());
        let ev = p
            .push_line(r#"1000.000002 <... read resumed> "hi", 4096) = 2 <0.0001>"#)
            .unwrap();
        assert_eq!(ev.name, "read");
        assert_eq!(ev.ret, Some(2));
        assert_eq!(ev.args.fd, Some(3));
    }

    #[test]
    fn fcntl_dup_keeps_source_and_records_returned_fd() {
        let (_, args, ret, errno) =
            parse_completed("fcntl(3</tmp/source>, F_DUPFD_CLOEXEC, 10) = 10 <0.0001>").unwrap();
        assert_eq!(ret, Some(10));
        assert!(errno.is_none());
        assert_eq!(args.fd, Some(3));
        assert_eq!(args.newfd, Some(10));
        assert!(args.flags.as_deref().unwrap_or_default().contains("DUP"));
    }

    #[test]
    fn parses_iovecs_and_scm_rights() {
        let (_, writev, _, _) = parse_completed("writev(4, [{iov_base=0x7fff0000, iov_len=4}, {iov_base=0x7fff0010, iov_len=8}], 2) = 12").unwrap();
        assert_eq!(writev.iovecs.len(), 2);
        assert_eq!(writev.iovecs[0].addr, 0x7fff0000);
        let (_, recv, _, _) = parse_completed("recvmsg(3, {msg_control=[{cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[7, 8]}]}, 0) = 1").unwrap();
        assert_eq!(recv.received_fds, vec![7, 8]);
    }

    #[test]
    fn live_parser_materializes_completed_calls_in_sequence() {
        let mut parser = LiveStraceParser::new(Config::default());
        let first = parser
            .push(r#"[pid 42] 1000.000001 openat(AT_FDCWD, "/tmp/input", O_RDONLY) = 3 <0.0001>"#)
            .unwrap();
        let second = parser
            .push(r#"[pid 42] 1000.000002 read(3, "ok", 2) = 2 <0.0001>"#)
            .unwrap();

        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        assert_eq!(first.process.pid, 42);
        assert_eq!(second.args.fd, Some(3));
        assert_eq!(parser.stats().lines, 2);
    }
}

fn parse_iovecs(s: &str) -> Vec<Iovec> {
    let mut out = Vec::new();
    for item in s.split("iov_base=").skip(1) {
        let addr = item
            .find("0x")
            .and_then(|i| {
                item[i..]
                    .split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                    .next()
            })
            .and_then(parse_hex_addr);
        let len = item
            .split("iov_len=")
            .nth(1)
            .and_then(|x| x.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|x| x.parse().ok());
        if let (Some(addr), Some(len)) = (addr, len) {
            out.push(Iovec { addr, len });
        }
    }
    out
}

fn parse_scm_rights(s: &str) -> Vec<i32> {
    let Some(rights) = s.split("SCM_RIGHTS").nth(1) else {
        return Vec::new();
    };
    let data = rights.split("cmsg_data=").nth(1).unwrap_or(rights);
    let data = data.split(']').next().unwrap_or(data);
    data.split(|c: char| !c.is_ascii_digit() && c != '-')
        .filter_map(|x| x.parse::<i32>().ok())
        .filter(|fd| *fd >= 0)
        .collect()
}
