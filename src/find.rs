use super::Layout;
use std::fs;
use std::path::Path;

pub fn find_packages(pattern: &str, layout: &Layout) {
    // DEBUG-MARK: FIND-SEARCH v1.
    if pattern.is_empty() {
        println!("spk: no pattern given (try: spk find <name>)");
        return;
    }
    if !Path::new(&layout.registry).is_dir() {
        println!("spk: nothing installed");
        return;
    }
    let pkgs = layout.registry.trim_end_matches('/');
    let entries = match fs::read_dir(pkgs) {
        Ok(entries) => entries,
        Err(_) => {
            println!("spk: nothing installed");
            return;
        }
    };
    let mut matches: Vec<(String, String)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let pkg = entry.file_name().to_string_lossy().to_string();
        if !pkg.contains(pattern) {
            continue;
        }
        let version = fs::read_to_string(dir.join("version")).unwrap_or_default();
        matches.push((pkg, version.trim().to_string()));
    }
    matches.sort();
    if matches.is_empty() {
        println!("spk: no packages match \"{}\"", pattern);
        return;
    }
    for (pkg, version) in matches {
        if version.is_empty() {
            println!("{}", pkg);
        } else {
            println!("{} v{}", pkg, version);
        }
    }
}