use super::Layout;
use std::fs;
use std::path::Path;

// [SPK-DEBUG-OK 2026-09-20] uninstall flow audited.
// Arch-like rules: remove exactly what the registry recorded (files+shims),
// prune empty parents, drop ld.so conf, refresh ldconfig. Protected system
// configs are never deleted (passwd/shadow/group/fstab/machine-id/hostname).
// Returns true on full success, false when the package was missing — the
// multi-package caller (`spk rm a b c`) uses this to keep going and exit 1
// at the end instead of aborting mid-list.
// DEBUG-MARK: RM-FLOW v1.
const PROTECTED_BASENAMES: &[&str] = &[
    "passwd",
    "shadow",
    "gshadow",
    "group",
    "fstab",
    "machine-id",
    "hostname",
    "hosts",
    "resolv.conf",
];

fn is_protected(path: &str) -> bool {
    // FIX 2026-09-20 RM-PROTECT-SCOPE: only guard real configs under /etc/.
    // The old basename-only check also matched binaries that share a name
    // (e.g. /usr/bin/passwd from a system package), leaving them behind on
    // `spk rm`. Configs like /etc/passwd, /etc/shadow, /etc/fstab,
    // /etc/machine-id, /etc/hostname are still never deleted.
    if !path.contains("/etc/") {
        return false;
    }
    let base = Path::new(path)
        .file_name()
        .map(|b| b.to_string_lossy().to_string())
        .unwrap_or_default();
    PROTECTED_BASENAMES.iter().any(|p| base == *p)
}

pub fn remove_package(name: &str, layout: &Layout) {
    if !try_remove_package(name, layout) {
        std::process::exit(1);
    }
}

pub fn try_remove_package(name: &str, layout: &Layout) -> bool {
    // [SPK-DEBUG-OK 2026-09-20] registry removal audited — see header.
    // DEBUG-MARK: RM-REGISTRY v1.
    if !Path::new(&layout.registry).is_dir() {
        return legacy_remove(name, layout);
    }

    let files = fs::read_to_string(format!("{}/files", layout.registry)).unwrap_or_default();
    let shims = fs::read_to_string(format!("{}/shims", layout.registry)).unwrap_or_default();
    let system_files = fs::read_to_string(format!("{}/system-files", layout.registry)).unwrap_or_default();

    let mut removed = 0;
    let mut skipped_protected = 0;
    let mut failed = 0;
    for line in files.lines().chain(shims.lines()).chain(system_files.lines()) {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        if is_protected(path) {
            skipped_protected += 1;
            continue;
        }
        if !in_scope(path, layout) {
            continue;
        }
        match fs::symlink_metadata(path) {
            Err(_) => continue,
            Ok(m) if m.file_type().is_dir() => {
                if fs::remove_dir(path).is_ok() {
                    removed += 1;
                    prune_empty_parents(path, layout);
                }
            }
            Ok(_) => {
                if fs::remove_file(path).is_ok() {
                    removed += 1;
                    prune_empty_parents(path, layout);
                } else {
                    failed += 1;
                }
            }
        }
    }
    if failed > 0 {
        println!("spk: warning: {} file(s) could not be removed (try sudo spk rm {})", failed, name);
        return false;
    }

    let _ = fs::remove_dir_all(&layout.appdir);
    let _ = fs::remove_dir_all(&layout.pkgdir);
    let _ = fs::remove_dir_all(&layout.registry);

    remove_lib_conf(name, layout);
    if !layout.user_mode && removed > 0 {
        let prefix = if layout.root.is_empty() { "/" } else { layout.root.as_str() };
        let status = if prefix == "/" {
            std::process::Command::new("ldconfig").status()
        } else {
            std::process::Command::new("ldconfig").arg("-r").arg(prefix).status()
        };
        if !matches!(status, Ok(code) if code.success()) {
            println!("spk: warning: ldconfig refresh failed - run ldconfig by hand");
        }
    }

    if removed == 0 {
        println!("spk: {} was already gone, cleaned up its records", name);
    } else {
        println!("spk: removed {} ({} files)", name, removed);
    }
    if skipped_protected > 0 {
        println!(
            "spk: kept {} protected config file(s) (passwd/shadow/fstab/...) — edit by hand if needed",
            skipped_protected
        );
    }
    true
}

fn prune_empty_parents(path: &str, layout: &Layout) {
    let stop = scope_root(layout);
    let mut current = match Path::new(path).parent() {
        Some(parent) => parent.to_path_buf(),
        None => return,
    };
    loop {
        let text = current.to_string_lossy().to_string();
        if text == stop || !text.starts_with(stop.as_str()) {
            break;
        }
        if fs::remove_dir(&current).is_err() {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
}

fn scope_root(layout: &Layout) -> String {
    if layout.user_mode {
        match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => home.trim_end_matches('/').to_string(),
            _ => String::from("/"),
        }
    } else if layout.root.is_empty() {
        String::from("/")
    } else {
        layout.root.clone()
    }
}

fn in_scope(path: &str, layout: &Layout) -> bool {
    let stop = scope_root(layout);
    if stop == "/" {
        return path.starts_with('/');
    }
    path == stop || path.starts_with(&format!("{}/", stop))
}

fn remove_lib_conf(name: &str, layout: &Layout) {
    if layout.user_mode {
        return;
    }
    let safe: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if safe.is_empty() {
        return;
    }
    let prefix = if layout.root.is_empty() { "/" } else { layout.root.as_str() };
    let spk_dir = format!("{}/usr/lib/spk/{}", prefix.trim_end_matches('/'), safe);
    if fs::remove_dir_all(&spk_dir).is_ok() {
        println!("spk: removed {}", spk_dir);
    }
    let conf = format!("{}/etc/ld.so.conf.d/spk-{}.conf", prefix.trim_end_matches('/'), safe);
    if fs::remove_file(&conf).is_ok() {
        println!("spk: removed {}", conf);
        let status = if prefix == "/" {
            std::process::Command::new("ldconfig").status()
        } else {
            std::process::Command::new("ldconfig").arg("-r").arg(prefix).status()
        };
        if !matches!(status, Ok(code) if code.success()) {
            println!("spk: warning: ldconfig refresh failed - run ldconfig by hand");
        }
    }
}

fn legacy_remove(name: &str, layout: &Layout) -> bool {
    // [SPK-DEBUG-OK 2026-09-20] legacy fallback audited: pre-registry installs
    // only left a single binary behind, so remove that + any stray dirs.
    // Returns false (caller exits 1) when nothing is found.
    // DEBUG-MARK: RM-LEGACY v1.
    remove_lib_conf(name, layout);
    let mut dirs: Vec<String> = Vec::new();
    if layout.user_mode {
        dirs.push(layout.shimdir.clone());
    } else {
        let prefix = if layout.root == "/" || layout.root.is_empty() {
            String::new()
        } else {
            layout.root.clone()
        };
        for dir in ["/usr/bin", "/usr/local/bin", "/bin"] {
            dirs.push(format!("{}{}", prefix, dir));
        }
    }
    for dir in &dirs {
        let path = format!("{}/{}", dir.trim_end_matches('/'), name);
        if fs::remove_file(&path).is_ok() {
            println!("spk: removed {}", path);
            let _ = fs::remove_dir_all(&layout.appdir);
            let _ = fs::remove_dir_all(&layout.pkgdir);
            let _ = fs::remove_dir_all(&layout.registry);
            return true;
        }
    }
    eprintln!("spk: could not find {}", name);
    false
}
