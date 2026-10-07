use std::fs;

pub fn update_packages(names: &[String], root: &str, user_mode: bool) -> bool {
    // DEBUG-MARK: UPDATE-FLOW v1.
    if names.is_empty() {
        return update_all(root, user_mode);
    }
    let mut failed: Vec<String> = Vec::new();
    for name in names {
        let layout = super::layout_for(root, user_mode, name);
        if !update_one(name, &layout) {
            failed.push(name.clone());
        }
    }
    if !failed.is_empty() {
        eprintln!("spk: update failed for: {}", failed.join(" "));
        return false;
    }
    true
}

fn installed_version(layout: &super::Layout) -> String {
    fs::read_to_string(format!("{}/version", layout.registry))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn installed_category(layout: &super::Layout) -> String {
    fs::read_to_string(format!("{}/category", layout.registry))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn latest_manifest(name: &str, layout: &super::Layout, base: &str) -> (String, String, String) {
    let cat = installed_category(layout);
    if !cat.is_empty() && cat != "misc" {
        let url = format!("{}/{}/{}/package.json", base, cat, name);
        if let Some(m) = super::http_get_opt(&url) {
            let mut c = super::read_field(&m, "category");
            if c.is_empty() {
                c = cat.clone();
            }
            return (c, m, format!("{}/{}/{}", base, cat, name));
        }
    }
    super::resolve_package(base, name)
}

fn update_one(name: &str, layout: &super::Layout) -> bool {
    let base = super::base_url();
    let current = installed_version(layout);
    if current.is_empty() {
        println!("spk: {} is not installed, installing...", name);
        super::get(name, layout);
        return true;
    }
    let (cat, manifest, _) = latest_manifest(name, layout, &base);
    let latest = super::read_field(&manifest, "version").trim().to_string();
    if latest.is_empty() {
        super::get(name, layout);
        return true;
    }
    if current == latest {
        println!("spk: {} v{} is already up to date", name, current);
        return true;
    }
    let show_cat = if cat.is_empty() { "misc".to_string() } else { cat };
    super::step(&format!("updating {} v{} -> v{} ({})", name, current, latest, show_cat));
    super::get(name, layout);
    true
}

fn update_all(root: &str, user_mode: bool) -> bool {
    let probe = super::layout_for(root, user_mode, "");
    let base_dir = probe.registry.trim_end_matches('/').to_string();
    let entries = match fs::read_dir(&base_dir) {
        Ok(e) => e,
        Err(_) => {
            println!("spk: nothing installed");
            return true;
        }
    };
    let mut pkgs: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let pkg = entry.file_name().to_string_lossy().to_string();
        if pkg.is_empty() {
            continue;
        }
        pkgs.push(pkg);
    }
    pkgs.sort();
    if pkgs.is_empty() {
        println!("spk: nothing installed");
        return true;
    }
    super::step(&format!("checking {} package(s) for updates...", pkgs.len()));
    let mut failed: Vec<String> = Vec::new();
    let mut updated = 0;
    for pkg in &pkgs {
        let layout = super::layout_for(root, user_mode, pkg);
        let before = installed_version(&layout);
        if !update_one(pkg, &layout) {
            failed.push(pkg.clone());
            continue;
        }
        let after = installed_version(&layout);
        if !before.is_empty() && !after.is_empty() && before != after {
            updated += 1;
        }
    }
    if !failed.is_empty() {
        eprintln!("spk: update failed for: {}", failed.join(" "));
        return false;
    }
    if updated == 0 {
        super::done_line("everything is already up to date");
    } else {
        super::done_line(&format!("updated {} package(s)", updated));
    }
    true
}
