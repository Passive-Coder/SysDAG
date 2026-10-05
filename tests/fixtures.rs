use std::path::{Path, PathBuf};

pub const CLEAN_TRACE: &str = r#"
1000.000001 openat(AT_FDCWD, "/guest/www/index.html", O_RDONLY) = 3</guest/www/index.html> <0.000010>
1000.000020 read(3</guest/www/index.html>, "ok\n", 4096) = 3 <0.000008>
1000.000030 close(3</guest/www/index.html>) = 0 <0.000004>
1000.000040 openat(AT_FDCWD, "/guest/www/page.txt", O_RDONLY) = 3</guest/www/page.txt> <0.000009>
1000.000050 read(3</guest/www/page.txt>, "static-payload\n", 4096) = 15 <0.000007>
1000.000060 close(3</guest/www/page.txt>) = 0 <0.000003>
1000.000070 openat(AT_FDCWD, "/guest/www/missing.txt", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000006>
1000.000080 write(1</dev/pts/0>, "done\n", 5) = 5 <0.000005>
"#;

#[allow(dead_code)]
pub const ATTACK_TRACE: &str = r#"
1000.000001 openat(AT_FDCWD, "/guest/www/index.html", O_RDONLY) = 3</guest/www/index.html> <0.000010>
1000.000020 read(3</guest/www/index.html>, "ok\n", 4096) = 3 <0.000008>
1000.000030 close(3</guest/www/index.html>) = 0 <0.000004>
1000.000040 openat(AT_FDCWD, "/guest/www/page.txt", O_RDONLY) = 3</guest/www/page.txt> <0.000009>
1000.000050 read(3</guest/www/page.txt>, "static-payload\n", 4096) = 15 <0.000007>
1000.000060 close(3</guest/www/page.txt>) = 0 <0.000003>
1000.000070 openat(AT_FDCWD, "/guest/www/missing.txt", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000006>
1000.000080 openat(AT_FDCWD, "/guest/decoy/secret.txt", O_RDONLY) = 3</guest/decoy/secret.txt> <0.000011>
1000.000090 read(3</guest/decoy/secret.txt>, "harmless-decoy-token\n", 4096) = 21 <0.000007>
1000.000100 close(3</guest/decoy/secret.txt>) = 0 <0.000003>
1000.000110 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4<socket:[12345]> <0.000020>
1000.000120 sendto(4<socket:[12345]>, "harmless-decoy-token\n", 21, 0, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("127.0.0.1")}, 16) = 21 <0.000015>
1000.000130 close(4<socket:[12345]>) = 0 <0.000004>
"#;

pub fn synthetic_trace(dir: &Path, name: &str, contents: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("create fixture directory");
    let path = dir.join(name);
    std::fs::write(&path, contents.trim_start()).expect("write synthetic trace");
    path
}
