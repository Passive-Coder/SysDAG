use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::canonical::{digest, Canon};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeLabels {
    pub family: String,
    pub op: String,
    pub result: String,
    pub resource_kind: String,
    pub flags: String,
    pub bytes: String,
    pub path_class: String,
}

pub fn syscall_class(name: &str) -> &'static str {
    match name {
        "open" | "openat" | "openat2" | "creat" | "stat" | "statx" | "lstat" | "fstat"
        | "newfstatat" | "access" | "faccessat" | "faccessat2" | "readlink" | "readlinkat"
        | "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" | "mkdir" | "mkdirat"
        | "chmod" | "fchmod" | "chown" | "chdir" | "getcwd" => "file",
        "read" | "write" | "pread64" | "pwrite64" | "readv" | "writev" | "preadv" | "pwritev"
        | "lseek" | "close" | "close_range" | "dup" | "dup2" | "dup3" | "fcntl" | "ioctl"
        | "pipe" | "pipe2" => "descriptor",
        "socket" | "connect" | "accept" | "accept4" | "bind" | "listen" | "sendto" | "recvfrom"
        | "sendmsg" | "recvmsg" | "sendmmsg" | "recvmmsg" | "send" | "recv" | "shutdown"
        | "getsockname" | "getpeername" | "setsockopt" | "getsockopt" => "network",
        "clone" | "clone3" | "fork" | "vfork" | "execve" | "execveat" | "wait4" | "waitid"
        | "exit" | "exit_group" | "kill" => "process",
        "mmap" | "mmap2" | "munmap" | "mprotect" | "brk" => "memory",
        _ => "other",
    }
}

pub fn operation_name(name: &str) -> String {
    match name {
        "open" | "openat" | "openat2" | "creat" => "FILE_OPEN",
        "stat" | "statx" | "lstat" | "fstat" | "newfstatat" => "FILE_STAT",
        "access" | "faccessat" | "faccessat2" => "FILE_ACCESS",
        "read" | "pread64" | "readv" | "preadv" => "FILE_READ",
        "write" | "pwrite64" | "writev" | "pwritev" => "FILE_WRITE",
        "close" | "close_range" => "FILE_CLOSE",
        "dup" | "dup2" | "dup3" => "FD_DUP",
        "fcntl" => "FD_FCNTL",
        "pipe" | "pipe2" => "PIPE_CREATE",
        "socket" => "NET_SOCKET",
        "connect" => "NET_CONNECT",
        "accept" | "accept4" => "NET_ACCEPT",
        "bind" => "NET_BIND",
        "listen" => "NET_LISTEN",
        "sendto" | "sendmsg" | "sendmmsg" | "send" => "NET_SEND",
        "recvfrom" | "recvmsg" | "recvmmsg" | "recv" => "NET_RECV",
        "clone" | "clone3" | "fork" | "vfork" => "PROCESS_CLONE",
        "execve" | "execveat" => "PROCESS_EXEC",
        "wait4" | "waitid" => "PROCESS_WAIT",
        "mmap" | "mmap2" => "MEM_MAP",
        "munmap" => "MEM_UNMAP",
        "mprotect" => "MEM_PROTECT",
        other => return other.to_uppercase(),
    }
    .to_string()
}

pub fn is_tracked(name: &str, classes: &[String]) -> bool {
    let family = syscall_class(name);
    family != "other" && classes.iter().any(|c| c == family)
}

pub fn byte_bucket(n: Option<i64>) -> &'static str {
    match n {
        None => "NONE",
        Some(x) if x < 0 => "NONE",
        Some(0) => "ZERO",
        Some(x) if x <= 64 => "1_64",
        Some(x) if x <= 512 => "65_512",
        Some(x) if x <= 4096 => "513_4096",
        Some(_) => "GT_4096",
    }
}

const EXPECTED_ERRNO: &[&str] = &[
    "ENOENT",
    "EAGAIN",
    "EWOULDBLOCK",
    "EINTR",
    "EEXIST",
    "EISDIR",
    "ENOTDIR",
    "ECONNREFUSED",
    "ECONNRESET",
    "EPIPE",
    "ETIMEDOUT",
];

pub fn result_class(ret: Option<i64>, errno: Option<&str>) -> &'static str {
    if let Some(e) = errno {
        return if EXPECTED_ERRNO.contains(&e) {
            "EXPECTED_ERROR"
        } else {
            "OTHER_ERROR"
        };
    }
    match ret {
        None => "UNKNOWN",
        Some(x) if x < 0 => "OTHER_ERROR",
        Some(_) => "SUCCESS",
    }
}

pub fn flags_bucket(flags: &str) -> &'static str {
    let text = flags.to_ascii_uppercase();
    if text.is_empty() || text == "0" || text == "NULL" {
        return "NONE";
    }
    let write = text.contains("O_WRONLY") || text.contains("O_RDWR");
    let create = text.contains("O_CREAT") || text.contains("O_TRUNC");
    if create && write {
        "CREATE_WRITE"
    } else if write {
        "WRITE"
    } else if text.contains("O_RDONLY") {
        "READ_ONLY"
    } else if text.contains("SOCK_STREAM") {
        "STREAM"
    } else if text.contains("SOCK_DGRAM") {
        "DGRAM"
    } else if text.contains("PROT_EXEC") {
        "EXEC"
    } else {
        "OTHER"
    }
}

pub fn classify_path(path: &str, app_root: &str) -> String {
    if path.is_empty() || path.starts_with("AT_") {
        return "NONE".into();
    }
    let normalized = normalize_path(path);
    if !app_root.is_empty() {
        let root = normalize_path(app_root);
        if normalized == root
            || normalized.starts_with(&(root.trim_end_matches('/').to_string() + "/"))
        {
            return "APP_ROOT".into();
        }
    }
    if normalized.starts_with("/tmp") || normalized.starts_with("/var/tmp") {
        return "TEMP".into();
    }
    if normalized.starts_with("/home")
        || normalized.starts_with("/root")
        || normalized.starts_with("/Users")
    {
        return "HOME".into();
    }
    if normalized.starts_with("/proc") {
        return "PROC".into();
    }
    if normalized.starts_with("/etc") {
        return "SYSTEM_CONFIG".into();
    }
    if normalized.starts_with("/dev") {
        return "DEV".into();
    }
    if normalized.contains("decoy") || normalized.contains("secret") {
        return "DECOY".into();
    }
    "OTHER".into()
}

fn normalize_path(path: &str) -> String {
    let p = Path::new(path);
    let mut out = Vec::new();
    let mut absolute = false;
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
        }
    }
    if absolute {
        format!("/{}", out.join("/"))
    } else {
        out.join("/")
    }
}

pub fn resource_kind(name: &str, fd_path: &str, sock_info: &str) -> &'static str {
    let decoded = format!("{fd_path} {sock_info}");
    if decoded.contains("socket")
        || decoded.contains("TCP")
        || decoded.contains("UDP")
        || decoded.contains("UNIX")
    {
        return "SOCKET";
    }
    if decoded.contains("pipe") {
        return "PIPE";
    }
    match syscall_class(name) {
        "network" => "SOCKET",
        "file" | "descriptor" => "FILE",
        "process" => "PROCESS",
        "memory" => "MEMORY",
        _ => "UNKNOWN",
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_labels(
    name: &str,
    path: &str,
    flags: &str,
    fd_path: &str,
    sock_info: &str,
    ret: Option<i64>,
    errno: Option<&str>,
    ret_bytes: Option<i64>,
    app_root: &str,
) -> NodeLabels {
    let path = if path.is_empty() { fd_path } else { path };
    let mut family = syscall_class(name).to_string();
    let mut op = operation_name(name);
    let kind = resource_kind(name, fd_path, sock_info);
    if matches!(
        name,
        "read" | "write" | "pread64" | "pwrite64" | "readv" | "writev"
    ) && kind == "SOCKET"
    {
        op = if name.contains("read") {
            "NET_RECV".into()
        } else {
            "NET_SEND".into()
        };
        family = "network".into();
    }
    let bytes = if matches!(
        name,
        "read"
            | "write"
            | "sendto"
            | "recvfrom"
            | "send"
            | "recv"
            | "pread64"
            | "pwrite64"
            | "sendmsg"
            | "recvmsg"
    ) {
        ret_bytes.or(if errno.is_none() { ret } else { None })
    } else {
        ret_bytes
    };
    let mut path_class = classify_path(path, app_root);
    if is_shell_path(path) {
        path_class = "SHELL".into();
    }
    NodeLabels {
        family,
        op,
        result: result_class(ret, errno).into(),
        resource_kind: kind.into(),
        flags: flags_bucket(flags).into(),
        bytes: byte_bucket(bytes).into(),
        path_class,
    }
}

pub fn label_digest(labels: &NodeLabels) -> String {
    digest(&Canon::map_from([
        ("bytes", Canon::str(&labels.bytes)),
        ("family", Canon::str(&labels.family)),
        ("flags", Canon::str(&labels.flags)),
        ("op", Canon::str(&labels.op)),
        ("path_class", Canon::str(&labels.path_class)),
        ("resource_kind", Canon::str(&labels.resource_kind)),
        ("result", Canon::str(&labels.result)),
    ]))
}

pub fn is_fd_allocator(name: &str) -> bool {
    matches!(
        name,
        "open"
            | "openat"
            | "openat2"
            | "creat"
            | "socket"
            | "accept"
            | "accept4"
            | "dup"
            | "dup2"
            | "dup3"
    )
}

pub fn is_shell_path(path: &str) -> bool {
    let base = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    matches!(
        base,
        "sh" | "bash" | "dash" | "zsh" | "csh" | "ksh" | "busybox"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_classes() {
        assert_eq!(classify_path("/etc/passwd", ""), "SYSTEM_CONFIG");
        assert_eq!(
            classify_path("/guest/www/index.html", "/guest/www"),
            "APP_ROOT"
        );
        assert_eq!(
            classify_path("/guest/decoy/secret.txt", "/guest/www"),
            "DECOY"
        );
        assert_eq!(classify_path("/tmp/x", ""), "TEMP");
    }

    #[test]
    fn byte_buckets() {
        assert_eq!(byte_bucket(Some(0)), "ZERO");
        assert_eq!(byte_bucket(Some(128)), "65_512");
        assert_eq!(byte_bucket(Some(8192)), "GT_4096");
    }
}
