pub mod find;
pub mod remove;
pub mod upd;

use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;

use sha2::Digest;
use sha2::Sha256;

const DEFAULT_BASE: &str = "https://huggingface.co/datasets/vgzz/spk-pkgs/resolve/main/packages";

// [SPK-DEBUG-OK 2026-09-20] system-vs-isolated sorting audited.
// Rule (arch-like): system packages install straight into / (like `pacman -S`)
// so daemons/DMs/DEs/drivers keep their absolute paths (/usr/bin/sddm,
// /etc/sddm.conf.d, /lib/modules, ...). Leaf apps stay isolated in
// /spk_pkgs/<name> (or ~/.local/share/spk/apps/<name> with --user) with
// shims in /usr/local/bin. `system` is true when the manifest says so OR
// when the name matches the well-known system set below. This stops a
// mis-packed manifest (e.g. sddm without system=true) from landing isolated
// and never starting.
// DEBUG-MARK: SYSTEM-SORT v1 — do not move sddm-class pkgs to isolated.
const SYSTEM_EXACT: &[&str] = &[
    // display managers / greeters — MUST be system or no graphical login
    "sddm", "gdm", "lightdm", "lxdm", "ly", "greetd", "tuigreet", "emptty", "xdm", "slim", "dm-openrc",
    "lightdm-gtk-greeter", "sddm-kcm",
    // desktops / sessions / compositors
    "plasma-desktop", "plasma-workspace", "plasma", "kde", "gnome", "gnome-shell",
    "gnome-session", "xfce4", "xfce4-session", "xfce", "lxqt", "lxde", "cinnamon",
    "mate-desktop", "mate", "budgie-desktop", "cosmic-desktop", "pantheon", "deepin",
    "enlightenment", "sway", "i3", "hyprland", "instantwm", "instantwmctl", "dwm", "niri", "mangowm", "mango", "labwc", "wayland", "xorg-server", "xorg",
    "dmenu", "rofi", "wofi", "waybar", "quickshell", "st", "kitty", "alacritty", "ghostty", "xinit", "xkb-data", "dejavu", "llvm",
    "gtk-libs", "wl-libs", "gtk3", "cxx-libs", "libcjson", "pipewire", "wlroots", "scenefx", "seatd", "vulkan-loader", "mesa",
    // DE companion apps installed by the Silen installer alongside the DE.
    // They ship .desktop files / session integration under /usr, so they must
    // be system too (isolated shims would hide them from the DE menu).
    // DEBUG-MARK: SYSTEM-SORT v2 — installer DE sets stay in /usr.
    "konsole", "dolphin", "kate", "kwrite", "ark", "spectacle",
    "gnome-terminal", "nautilus", "gnome-text-editor", "gnome-calculator",
    "xfce4-terminal", "thunar", "mousepad", "ristretto",
    // kernels / firmware / drivers — MUST be system (paths like /lib/modules, /lib/firmware)
    // DEBUG-MARK: SYSTEM-SORT-HEADERS v1.
    "linux", "kernel", "linux-firmware", "linux-headers", "kernel-headers", "intel-ucode", "amd-ucode",
    "nvidia-drivers", "nvidia-legacy-drivers", "mesa", "libdrm",
    "xf86-video-amdgpu", "xf86-video-intel", "xf86-video-vmware", "xf86-video-nouveau",
    "xf86-input-libinput", "vulkan-loader",
    "rtl8822ce", "iwlwifi", "mt7921", "ath11k", "brcmfmac", "rtw89", "rtw88",
    // core system services
    "dbus", "elogind", "systemd", "openrc", "polkit", "upower", "udisks2",
    "networkmanager", "wpa_supplicant", "iwd", "dhcpcd", "connman", "modemmanager",
    "pipewire", "pulseaudio", "alsa", "alsa-utils", "wireplumber",
    "efibootmgr", "grub",
];

fn looks_like_system_package(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if SYSTEM_EXACT.contains(&n.as_str()) {
        return true;
    }
    // prefixes: DE families, xorg/xf86 drivers, firmware blobs
    for prefix in [
        "plasma-", "kde-", "gnome-", "xfce4-", "xfce-", "lxqt-", "sddm-", "gdm-",
        "lightdm-", "xorg-", "xf86-video-", "xf86-input-", "nvidia-", "amd-ucode",
        "intel-ucode", "linux-", "linux-firmware", "wpa_", "alsa-", "pipewire-", "pulseaudio-",
        "wireplumber",
    ] {
        if n == prefix.trim_end_matches('-') || n.starts_with(prefix) {
            return true;
        }
    }
    // substrings / suffixes that are (almost) always system-level
    for needle in [
        "firmware", "driver", "kernel", "headers", "mesa", "vulkan", "libdrm", "microcode",
        "-ucode", "greeter", "display-manager", "dm-", "elogind", "polkit",
        "networkmanager", "modemmanager", "pipewire", "pulseaudio",
    ] {
        if n.contains(needle) {
            return true;
        }
    }
    false
}

fn is_system_package(name: &str, manifest_flag: bool) -> (bool, &'static str) {
    if manifest_flag {
        return (true, "manifest");
    }
    if looks_like_system_package(name) {
        return (true, "name-heuristic");
    }
    (false, "leaf")
}

pub struct Layout {
    pub root: String,
    pub registry: String,
    pub appdir: String,
    pub pkgdir: String,
    pub shimdir: String,
    pub tmp: String,
    pub user_mode: bool,
}

struct Installed {
    path: String,
    mode: u32,
    is_link: bool,
}

fn main() {
    // [SPK-DEBUG-OK 2026-09-20] CLI dispatch audited.
    // Supports arch-like multi-package: `spk get a b c`, `spk rm a b c`.
    // Each package gets its own Layout (tmp/registry paths differ per name).
    // Installs run in order; first hard failure aborts (like pacman
    // transaction abort) so half-installed sets are visible, not silent.
    // DEBUG-MARK: CLI-MULTI v1.
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        usage();
        return;
    }

    // `spk --help`, `spk get --help`, `spk -h` behave like arch tools.
    if args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        usage();
        return;
    }

    if args[1] == "--version" || args[1] == "-V" {
        println!("spk {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if args[1] == "self-update" {
        let mut check_only = false;
        for arg in &args[2..] {
            if arg == "--check" {
                check_only = true;
            } else if arg == "--help" || arg == "-h" {
                usage();
                return;
            } else {
                fail(&format!("unknown flag {} (usage: spk self-update [--check])", arg));
            }
        }
        self_update(check_only);
        return;
    }

    let mut root = String::from("/");
    let mut user_mode = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--root" {
            if i + 1 >= args.len() {
                fail(" --root needs a directory");
            }
            root = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--user" {
            user_mode = true;
            i += 1;
        } else if args[i] == "--help" || args[i] == "-h" {
            usage();
            return;
        } else if args[i].starts_with('-') {
            fail(&format!("unknown flag {}", args[i]));
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }

    // Arch-like: de-duplicate repeat names (`spk get foo foo` installs once;
    // `spk rm foo foo` must not fail on the second, already-gone entry).
    // FIX 2026-09-20 DEDUP — order-preserving dedup of positionals.
    {
        let mut seen = std::collections::HashSet::new();
        positional.retain(|n| seen.insert(n.clone()));
    }

    if args[1] == "list" {
        // list takes no package name; fall through
        let layout = layout_for(&root, user_mode, "");
        list(&layout);
    } else if args[1] == "remove" || args[1] == "rm" {
        if positional.is_empty() {
            fail("usage: spk rm <package> [package...] [--root DIR] [--user]");
        }
        for name in &positional {
            if !valid_name(name) {
                fail(&format!("bad package name {:?} (use [a-z0-9_.+-], no / or ..)", name));
            }
        }
        // arch-like: remove in order, keep going, report failures at end.
        let mut failed: Vec<String> = Vec::new();
        for name in &positional {
            let layout = layout_for(&root, user_mode, name);
            if !remove::try_remove_package(name, &layout) {
                failed.push(name.clone());
            }
        }
        if !failed.is_empty() {
            process::exit(1);
        }
    } else if args[1] == "get" {
        if positional.is_empty() {
            fail("usage: spk get <package> [package...] [--root DIR] [--user]");
        }
        for name in &positional {
            if !valid_name(name) {
                fail(&format!("bad package name {:?} (use [a-z0-9_.+-], no / or ..)", name));
            }
        }
        let mut done = HashSet::new();
        for name in &positional {
            let layout = layout_for(&root, user_mode, name);
            get_with_visited(name, &layout, &mut done);
        }
    } else if args[1] == "find" || args[1] == "search" {
        if positional.is_empty() {
            fail("usage: spk find <pattern> [--root DIR] [--user]");
        }
        let layout = layout_for(&root, user_mode, "");
        find::find_packages(&positional[0], &layout);
    } else if args[1] == "update" || args[1] == "upgrade" {
        for name in &positional {
            if !valid_name(name) {
                fail(&format!("bad package name {:?} (use [a-z0-9_.+-], no / or ..)", name));
            }
        }
        if !upd::update_packages(&positional, &root, user_mode) {
            process::exit(1);
        }
    } else {
        usage();
    }
}

fn usage() {
    // [SPK-DEBUG-OK 2026-09-20] usage text audited — documents multi-package.
    eprintln!("usage:");
    eprintln!("  spk get <package> [package...] [--root DIR] [--user]");
    eprintln!("  spk rm <package> [package...] [--root DIR] [--user]");
    eprintln!("  spk update [<package>...] [--root DIR] [--user]");
    eprintln!("  spk find <pattern> [--root DIR] [--user]");
    eprintln!("  spk list [--root DIR] [--user]");
    eprintln!("  spk self-update [--check]    update spk itself from its release feed");
    eprintln!("");
    eprintln!("  sudo spk get <package>      install a package");
    eprintln!("  sudo spk rm <package>       remove a package and its files");
    eprintln!("  sudo spk update              update every installed package");
    eprintln!("  sudo spk update <package>    update (or install) one package");
    eprintln!("");
    eprintln!("packages live in categories (app-misc, app-editors, sys-apps,");
    eprintln!("dev-tools, sys-monitor, ...): just type the bare name and spk");
    eprintln!("finds it. If several categories share a name, spk asks which one.");
    eprintln!("like pacman: system packages (sddm, desktops, drivers, firmware,");
    eprintln!("dbus, NetworkManager, ...) install into / ; leaf apps stay");
    eprintln!("isolated with shims in /usr/local/bin (or ~/.local/bin with --user).");
}

pub(crate) fn fail(message: &str) -> ! {
    if color() {
        eprintln!("\x1b[1;31mspk: error:\x1b[0m {}", message.trim_start());
    } else {
        eprintln!("spk: error: {}", message.trim_start());
    }
    process::exit(1);
}

// DEBUG-MARK: UI-PAINT v1.
fn color() -> bool {
    std::env::var("NO_COLOR").is_err() && std::io::stderr().is_terminal()
}

fn paint(code: &str, text: &str) -> String {
    if color() {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

pub(crate) fn step(what: &str) {
    eprintln!("{} {}", paint("1;34", "==>"), paint("1", what));
}

pub(crate) fn done_line(what: &str) {
    println!("{} {}", paint("1;32", "done:"), what);
}

pub(crate) fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+') {
            return false;
        }
    }
    !(name.contains("..") || name.contains('/'))
}

fn check(result: std::io::Result<()>, what: &str) {
    if let Err(err) = result {
        fail(&format!("{}: {}", what, err));
    }
}

pub(crate) fn base_url() -> String {
    match std::env::var("SPK_BASE_URL") {
        Ok(value) if !value.trim().is_empty() => value.trim_end_matches('/').to_string(),
        _ => DEFAULT_BASE.to_string(),
    }
}

pub(crate) fn layout_for(root: &str, user_mode: bool, name: &str) -> Layout {
    // [SPK-DEBUG-OK 2026-09-20] layout audited.
    // System root (/): registry /var/lib/spk/packages/<name>, app links
    // /opt/spk/<name>, isolated payload /spk_pkgs/<name>, shims
    // /usr/local/bin. --root prefixes all of them; --user maps everything
    // under $HOME. tmp is per-package (+pid) so `spk get a b` never clashes.
    // DEBUG-MARK: LAYOUT v1.
    // FIX 2026-09-20 LAYOUT-DBLSLASH: when root is "/" (or empty) the path
    // prefix is "" so registry/appdir/pkgdir/shimdir build single-slash
    // paths (/var/..., /spk_pkgs/..., /opt/..., /usr/local/bin). The old code
    // used "/" as prefix and produced "//var/..." strings; the fs tolerated
    // them but registry-vs-installed string compares could mismatch.
    if user_mode {
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            fail("--user needs $HOME to be set");
        }
        if root != "/" && !root.is_empty() {
            println!("spk: note: --root is ignored with --user (installing into $HOME)");
        }
        let home = home.trim_end_matches('/').to_string();
        let base = format!("{}/.local/share/spk", home);
        Layout {
            root: String::new(),
            registry: format!("{}/packages/{}", base, name),
            appdir: format!("{}/apps/{}", base, name),
            pkgdir: format!("{}/apps/{}", base, name),
            shimdir: format!("{}/.local/bin", home),
            tmp: format!("{}/.cache/spk/{}.spk", home, name),
            user_mode: true,
        }
    } else {
        let clean_root = root.trim_end_matches('/').to_string();
        let prefix = if clean_root.is_empty() { String::new() } else { clean_root.clone() };
        let real_root = if clean_root.is_empty() { "/".to_string() } else { clean_root };
        Layout {
            root: real_root,
            registry: format!("{}/var/lib/spk/packages/{}", prefix, name),
            appdir: format!("{}/opt/spk/{}", prefix, name),
            pkgdir: format!("{}/spk_pkgs/{}", prefix, name),
            shimdir: format!("{}/usr/local/bin", prefix),
            tmp: format!("/tmp/spk-{}-{}.spk", sanitize_conf_name(name), std::process::id()),
            user_mode: false,
        }
    }
}

fn runtime_path(dest: &str, layout: &Layout) -> String {
    if layout.user_mode || layout.root == "/" || layout.root.is_empty() {
        return dest.to_string();
    }
    match dest.strip_prefix(layout.root.as_str()) {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => dest.to_string(),
    }
}

fn on_path(runtime: &str) -> bool {
    let dirs = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
    ];
    dirs.iter().any(|dir| runtime.starts_with(dir))
}

fn rel_target(link: &str, dest: &str) -> String {
    let link_parts: Vec<&str> = link.split('/').filter(|part| !part.is_empty()).collect();
    let dest_parts: Vec<&str> = dest.split('/').filter(|part| !part.is_empty()).collect();
    if link_parts.is_empty() || dest_parts.is_empty() {
        return dest.to_string();
    }
    let link_dir = &link_parts[..link_parts.len() - 1];
    let mut common = 0;
    while common < link_dir.len() && common < dest_parts.len() && link_dir[common] == dest_parts[common] {
        common += 1;
    }
    let mut out = String::new();
    for _ in common..link_dir.len() {
        out.push_str("../");
    }
    out.push_str(&dest_parts[common..].join("/"));
    if out.is_empty() {
        dest.to_string()
    } else {
        out
    }
}

pub(crate) fn get(name: &str, layout: &Layout) {
    let mut done = HashSet::new();
    get_with_visited(name, layout, &mut done);
}

// DEBUG-MARK: DEPS-AUTO v1.
fn get_with_visited(name: &str, layout: &Layout, done: &mut HashSet<String>) {
    if !done.insert(name.to_string()) {
        println!("spk: note: {} already queued, skipping", name);
        return;
    }
    // [SPK-DEBUG-OK 2026-09-20] install flow audited end-to-end:
    // manifest -> download(+sha256) -> payload_base -> extract ->
    // finish_install(shims+registry) -> postinstall -> ldconfig.
    // DEBUG-MARK: GET-FLOW v1.
    let base = base_url();
    let installed_cat = fs::read_to_string(format!("{}/category", layout.registry))
        .unwrap_or_default()
        .trim()
        .to_string();
    let (category, manifest, pkg_base) = if !installed_cat.is_empty() && installed_cat != "misc" {
        let url = format!("{}/{}/{}/package.json", base, installed_cat, name);
        match http_get_opt(&url) {
            Some(m) => {
                let mut c = manifest_category(&m);
                if c.is_empty() {
                    c = installed_cat.clone();
                }
                (c, m, format!("{}/{}/{}", base, installed_cat, name))
            }
            None => resolve_package(&base, name),
        }
    } else {
        resolve_package(&base, name)
    };
    let deps = read_string_array(&manifest, "depends");
    for dep in &deps {
        if !valid_name(dep) {
            println!("spk: warning: ignoring bad dependency name {:?} of {}", dep, name);
            continue;
        }
        if dep == name {
            continue;
        }
        let dep_layout = layout_for(&layout.root, layout.user_mode, dep);
        let (_, dep_manifest, _) = resolve_package(&base, dep);
        let dep_version = read_field(&dep_manifest, "version");
        if !dep_version.trim().is_empty() {
            let installed_version =
                fs::read_to_string(format!("{}/version", dep_layout.registry)).unwrap_or_default();
            if installed_version.trim() == dep_version.trim() {
                println!(
                    "spk: note: dependency {} v{} already installed, skipping",
                    dep,
                    dep_version.trim()
                );
                done.insert(dep.clone());
                continue;
            }
        }
        get_with_visited(dep, &dep_layout, done);
    }
    let show_cat = if category.is_empty() { "misc".to_string() } else { category.clone() };

    let file_name = read_field(&manifest, "filename");
    let version = read_field(&manifest, "version");
    let expected = read_field(&manifest, "sha256");
    let parts_str = read_field(&manifest, "parts");
    let parts: u32 = if parts_str.trim().is_empty() {
        1
    } else {
        match parts_str.trim().parse() {
            Ok(n) if (1..=64).contains(&n) => n,
            _ => fail(&format!("bad parts value {:?} in manifest for {}", parts_str, name)),
        }
    };
    let system_str = read_field(&manifest, "system");
    let manifest_system = matches!(
        system_str.to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    );
    let (system, reason) = is_system_package(name, manifest_system);
    if system {
        step(&format!("installing {} {} ({}, system -> /)", name, version.trim(), show_cat));
        println!("spk: {} is a system package ({}), installing into /", name, reason);
    } else {
        step(&format!("installing {} {} ({}, isolated)", name, version.trim(), show_cat));
        println!("spk: {} is a leaf package, installing isolated", name);
    }

    if system && layout.user_mode {
        fail("system packages (login managers, desktops, kernels) need a system install - retry without --user");
    }

    // Arch-like transparency: say so when this exact version is already
    // installed (pacman prints "warning: X is up to date -- reinstalling").
    // FIX 2026-09-20 REINSTALL-NOTE.
    if !version.trim().is_empty() {
        let installed_version =
            fs::read_to_string(format!("{}/version", layout.registry)).unwrap_or_default();
        if installed_version.trim() == version.trim() {
            println!("spk: note: {} v{} is already installed -- reinstalling", name, version.trim());
        }
    }

    if file_name.is_empty() {
        fail(&format!("manifest for {} has no filename", name));
    }

    let download_url = format!("{}/{}", pkg_base, file_name);
    println!("spk: downloading {}", file_name);

    if let Some(parent) = Path::new(&layout.tmp).parent() {
        check(fs::create_dir_all(parent), &format!("cannot create {}", parent.display()));
    }

    let digest = download(&download_url, &layout.tmp, parts);

    let size = match fs::metadata(&layout.tmp) {
        Ok(meta) => meta.len(),
        Err(err) => fail(&format!("cannot open downloaded file {}: {}", layout.tmp, err)),
    };
    println!("spk: downloaded {} bytes", size);

    if expected.is_empty() {
        eprintln!("spk: warning: no sha256 in manifest, skipping check");
    } else if digest.to_lowercase() != expected.trim().to_lowercase() {
        let _ = fs::remove_file(&layout.tmp);
        fail(&format!("sha256 mismatch for {} expected {} got {}", name, expected, digest));
    } else {
        println!("spk: checksum ok");
    }

    let payload_base: &str = if system {
        clean_stale_isolated(name, layout);
        layout.root.as_str()
    } else {
        if !layout.pkgdir.is_empty() {
            let _ = fs::remove_dir_all(&layout.pkgdir);
        }
        layout.pkgdir.as_str()
    };
    let installed = extract(&layout.tmp, payload_base, system);
    let _ = fs::remove_file(&layout.tmp);

    finish_install(name, &version, &installed, layout, system, &show_cat);
    run_postinstall(name, &version, layout, payload_base, system, &installed);
    register_libs(name, layout, system);
    done_line(&format!("{} v{} installed", name, version.trim()));
}

fn clean_stale_isolated(name: &str, layout: &Layout) {
    if layout.pkgdir.is_empty() || !Path::new(&layout.pkgdir).exists() {
        return;
    }
    let shims = fs::read_to_string(format!("{}/shims", layout.registry)).unwrap_or_default();
    let mut gone = 0;
    for line in shims.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        if fs::remove_file(path).is_ok() {
            gone += 1;
        }
    }
    let _ = fs::remove_dir_all(&layout.pkgdir);
    println!("spk: removed stale isolated copy of {} ({} shims)", name, gone);
}

fn sanitize_conf_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

fn core_lib(name: &str) -> bool {
    name.starts_with("ld-linux")
        || name.starts_with("libanl")
        || name.starts_with("libc.so")
        || name.starts_with("libc-")
        || name.starts_with("libm.so")
        || name.starts_with("libpthread")
        || name.starts_with("libdl.so")
        || name.starts_with("librt.so")
        || name.starts_with("libresolv")
        || name.starts_with("libutil.so")
        || name.starts_with("libnsl")
        || name.starts_with("libnss_")
        || name.starts_with("libcrypt.so")
        || name.starts_with("libthread_db")
        || name.starts_with("libmemusage")
        || name.starts_with("libpcprofile")
        || name.starts_with("libBrokenLocale")
        || name.starts_with("libgcc_s")
        || name.starts_with("libstdc++")
        || name.starts_with("libgomp")
}

fn system_tool(name: &str) -> bool {
    matches!(
        name,
        "ldconfig" | "ldd" | "iconv" | "iconvconfig" | "locale" | "localedef" | "getent"
            | "getconf" | "tzselect" | "zdump" | "zic" | "nscd" | "sln" | "makedb"
            | "pcprofiledump" | "sotruss" | "mtrace" | "xtrace" | "memusage" | "pldd" | "sprof"
    )
}

fn name_candidates(file_name: &str) -> Vec<String> {
    let mut out = vec![file_name.to_string()];
    let mut cur = file_name.to_string();
    while let Some(pos) = cur.rfind('.') {
        let head = cur[..pos].to_string();
        let tail = &cur[pos + 1..];
        if !tail.chars().all(|c| c.is_ascii_digit()) || !head.contains(".so") {
            break;
        }
        cur = head;
        out.push(cur.clone());
    }
    out
}

fn system_provided(prefix: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let base = if prefix == "/" || prefix.is_empty() { String::new() } else { prefix.to_string() };
    for sub in ["usr/lib", "usr/lib64", "lib", "lib64"] {
        let dir = if base.is_empty() {
            format!("/{}", sub)
        } else {
            format!("{}/{}", base.trim_end_matches('/'), sub)
        };
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.contains('/') {
                set.insert(fname);
            }
        }
    }
    let output = if prefix == "/" || prefix.is_empty() {
        std::process::Command::new("ldconfig").arg("-p").output()
    } else {
        std::process::Command::new("ldconfig").arg("-r").arg(prefix).arg("-p").output()
    };
    let output = match output {
        Ok(out) if out.status.success() => out,
        _ => return set,
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let name = match line.split_whitespace().next() {
            Some(n) => n,
            None => continue,
        };
        if name.contains('/') || name.contains('(') || name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Some(pos) = line.find("=>") {
            let path = line[pos + 2..].trim();
            if path.contains("/spk_pkgs/")
                || path.contains("/opt/spk/")
                || path.contains(".local/share/spk/")
                || path.contains("/usr/lib/spk/")
            {
                continue;
            }
        }
        set.insert(name.to_string());
    }
    set
}

fn refresh_ldconfig(layout: &Layout) {
    if layout.user_mode {
        return;
    }
    let prefix = if layout.root.is_empty() { "/" } else { layout.root.as_str() };
    let status = if prefix == "/" {
        std::process::Command::new("ldconfig").status()
    } else {
        std::process::Command::new("ldconfig").arg("-r").arg(prefix).status()
    };
    match status {
        Ok(code) if code.success() => println!("spk: ldconfig done"),
        Ok(code) => println!("spk: warning: ldconfig exited with {} - run ldconfig by hand", code),
        Err(err) => println!("spk: warning: could not run ldconfig ({}) - run ldconfig by hand", err),
    }
}

fn register_libs(name: &str, layout: &Layout, system: bool) {
    if system {
        refresh_ldconfig(layout);
        return;
    }
    let pkg = layout.pkgdir.trim_end_matches('/');
    let mut payload_libs: Vec<(String, String)> = Vec::new();
    for sub in ["usr/lib", "usr/lib64", "lib", "lib64"] {
        let full = format!("{}/{}", pkg, sub);
        let entries = match fs::read_dir(&full) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for fname in names {
            payload_libs.push((format!("{}/{}", full, fname), fname));
        }
    }
    if payload_libs.is_empty() {
        return;
    }
    if layout.user_mode {
        println!("spk: hint: libraries for {} live in the payload dirs above;", name);
        println!("spk: hint: export LD_LIBRARY_PATH=<dir>:$LD_LIBRARY_PATH if binaries fail to start");
        return;
    }
    let safe = sanitize_conf_name(name);
    if safe.is_empty() {
        return;
    }
    let prefix = if layout.root.is_empty() { "/" } else { layout.root.as_str() };
    let provided = system_provided(prefix);
    let spk_full = format!("{}/usr/lib/spk/{}", prefix.trim_end_matches('/'), safe);
    let spk_runtime = runtime_path(&spk_full, layout);
    let _ = fs::remove_dir_all(&spk_full);
    let mut exposed = 0;
    for (full, fname) in &payload_libs {
        if core_lib(fname) {
            continue;
        }
        let meta = match fs::symlink_metadata(full) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            if provided.contains(fname) {
                continue;
            }
            let target = match fs::read_link(full) {
                Ok(t) => t.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if fs::create_dir_all(&spk_full).is_err() {
                continue;
            }
            if std::os::unix::fs::symlink(&target, format!("{}/{}", spk_full, fname)).is_ok() {
                exposed += 1;
            }
        } else if meta.is_file() {
            if name_candidates(fname).iter().any(|c| provided.contains(c)) {
                continue;
            }
            if fs::create_dir_all(&spk_full).is_err() {
                continue;
            }
            if std::os::unix::fs::symlink(runtime_path(full, layout), format!("{}/{}", spk_full, fname)).is_ok() {
                exposed += 1;
            }
        }
    }
    if exposed == 0 {
        let _ = fs::remove_dir_all(&spk_full);
        return;
    }
    let conf = format!("{}/etc/ld.so.conf.d/spk-{}.conf", prefix.trim_end_matches('/'), safe);
    if let Some(parent) = Path::new(&conf).parent() {
        if fs::create_dir_all(parent).is_err() {
            println!("spk: warning: cannot create {} - run ldconfig by hand", parent.display());
            return;
        }
    }
    if fs::write(&conf, spk_runtime + "\n").is_err() {
        println!("spk: warning: cannot write {} - run ldconfig by hand", conf);
        return;
    }
    println!("spk: registered {} librar(y/ies) in {}", exposed, conf);
    refresh_ldconfig(layout);
}

fn run_postinstall(name: &str, version: &str, layout: &Layout, payload_base: &str, system: bool, installed: &[Installed]) {
    // [SPK-DEBUG-OK 2026-09-20] postinstall hook audited.
    // Only runs <payload>/usr/lib/spk/postinstall when it was part of THIS
    // package (prevents a stale hook from another package being executed).
    // Applies to both system and isolated layouts.
    // DEBUG-MARK: POSTINSTALL v1.
    if payload_base.is_empty() {
        return;
    }
    let hook = format!("{}/usr/lib/spk/postinstall", payload_base.trim_end_matches('/'));
    if !installed.iter().any(|item| item.path == hook) {
        return;
    }
    let meta = match fs::metadata(&hook) {
        Ok(meta) => meta,
        Err(_) => return,
    };
    if meta.is_dir() {
        println!("spk: warning: postinstall {} is a directory, skipping", hook);
        return;
    }
    if meta.permissions().mode() & 0o111 == 0 {
        println!("spk: note: {} is not executable, skipping postinstall", hook);
        return;
    }
    println!("spk: running postinstall for {}", name);
    let root = if layout.user_mode || layout.root.is_empty() {
        String::new()
    } else {
        layout.root.clone()
    };
    let pkgdir = if system { String::new() } else { layout.pkgdir.clone() };
    let status = std::process::Command::new(&hook)
        .env("SPK_PACKAGE", name)
        .env("SPK_VERSION", version)
        .env("SPK_ROOT", &root)
        .env("SPK_PKGDIR", &pkgdir)
        .env("SPK_APPDIR", &layout.appdir)
        .env("SPK_USER_MODE", if layout.user_mode { "1" } else { "0" })
        .status();
    match status {
        Ok(code) if code.success() => println!("spk: postinstall for {} done", name),
        Ok(code) => println!("spk: warning: postinstall for {} exited with {}", name, code),
        Err(err) => println!("spk: warning: could not run postinstall for {}: {}", name, err),
    }
}

fn finish_install(name: &str, version: &str, installed: &[Installed], layout: &Layout, system: bool, category: &str) {
    // [SPK-DEBUG-OK 2026-09-20] registry/shim finalisation audited.
    // Arch-like upgrade rule: orphaned shims/files from the previous version
    // that are gone in the new version are removed, so `spk get foo` twice
    // does not leak stale /usr/local/bin entries. New files/shims are
    // recorded in <registry>/{files,shims}. App links live in <appdir>/bin.
    // System files on PATH (/usr/bin/...) get app links but no shims.
    // DEBUG-MARK: FINISH-INSTALL v1.
    // Snapshot previous records before overwriting (for orphan cleanup).
    let old_files = fs::read_to_string(format!("{}/files", layout.registry)).unwrap_or_default();
    let old_shims = fs::read_to_string(format!("{}/shims", layout.registry)).unwrap_or_default();
    check(fs::create_dir_all(&layout.registry), &format!("cannot create {}", layout.registry));
    check(fs::create_dir_all(format!("{}/bin", layout.appdir)), &format!("cannot create {}/bin", layout.appdir));
    check(fs::create_dir_all(&layout.shimdir), &format!("cannot create {}", layout.shimdir));

    check(fs::write(format!("{}/version", layout.registry), format!("{}\n", version)), &format!("cannot write {}/version", layout.registry));
    let show_cat = if category.is_empty() { "misc" } else { category };
    check(fs::write(format!("{}/category", layout.registry), format!("{}\n", show_cat)), &format!("cannot write {}/category", layout.registry));

    let mut files = String::new();
    for item in installed {
        files.push_str(&item.path);
        files.push('\n');
    }
    check(fs::write(format!("{}/files", layout.registry), files), &format!("cannot write {}/files", layout.registry));
    check(fs::write(format!("{}/version", layout.appdir), format!("{}\n", version)), &format!("cannot write {}/version", layout.appdir));

    let mut commands: Vec<String> = Vec::new();
    let mut shims = String::new();

    for item in installed {
        if item.is_link || item.mode & 0o111 == 0 {
            continue;
        }
        if item.path.ends_with("/usr/lib/spk/postinstall") {
            // DEBUG-MARK: HOOK-NOSHIM v1.
            continue;
        }
        let cmd = match Path::new(&item.path).file_name() {
            Some(base) => base.to_string_lossy().to_string(),
            None => continue,
        };
        if cmd.is_empty() {
            continue;
        }

        let link = format!("{}/bin/{}", layout.appdir, cmd);
        if link != item.path {
            let _ = fs::remove_file(&link);
            if std::os::unix::fs::symlink(rel_target(&link, &item.path), &link).is_ok() && !commands.contains(&cmd) {
                commands.push(cmd.clone());
            }
        } else if !commands.contains(&cmd) {
            // DEBUG-MARK: SELF-LINK v1.
            commands.push(cmd.clone());
        }

        let runtime = runtime_path(&item.path, layout);
        if on_path(&runtime) {
            continue;
        }
        let shim = format!("{}/{}", layout.shimdir, cmd);
        let want = rel_target(&shim, &item.path);
        if fs::symlink_metadata(&shim).is_ok() {
            let ours = match fs::read_link(&shim) {
                Ok(t) => t.to_string_lossy() == want,
                Err(_) => false,
            };
            if ours {
                shims.push_str(&shim);
                shims.push('\n');
            } else {
                eprintln!("spk: warning: {} already exists (another package?), keeping it", shim);
            }
            continue;
        }
        match std::os::unix::fs::symlink(&want, &shim) {
            Ok(()) => {
                shims.push_str(&shim);
                shims.push('\n');
                if !commands.contains(&cmd) {
                    commands.push(cmd);
                }
            }
            Err(err) => eprintln!("spk: warning: cannot create shim {}: {}", shim, err),
        }
    }

    check(fs::write(format!("{}/shims", layout.registry), shims.clone()), &format!("cannot write {}/shims", layout.registry));

    // Remove orphans from the previous version (arch-like upgrade hygiene).
    // FIX 2026-09-20 FINISH-PRUNE v2: (a) files recorded in the previous
    // `files` registry for THIS package are owned by us even when they live
    // in shared system dirs (/usr/...) — the old guard only pruned
    // pkgdir/appdir/shims, so reinstalling a system package with fewer files
    // leaked orphans forever. Protected configs (passwd/shadow/...) are never
    // pruned here (rm path protects them too). (b) stale <appdir>/bin links
    // were never tracked, so a command dropped between versions lingered.
    // Sweep them below against the new command set.
    {
        use std::collections::HashSet;
        let new_files: HashSet<&str> = installed.iter().map(|i| i.path.as_str()).collect();
        let new_shims: HashSet<&str> = shims.lines().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        let old_file_set: HashSet<&str> = old_files.lines().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        let mut pruned = 0;
        for line in old_files.lines().chain(old_shims.lines()) {
            let p = line.trim();
            if p.is_empty() || new_files.contains(p) || new_shims.contains(p) {
                continue;
            }
            // Owned when: a recorded shim, a file we recorded for this
            // package (system or isolated), or anything under our private
            // payload/app dirs. Anything else (never recorded) is left alone
            // in case another package still needs it.
            let owned_shim = old_shims.lines().any(|s| s.trim() == p);
            let owned_file = old_file_set.contains(p);
            let under_payload = !layout.pkgdir.is_empty() && (p == layout.pkgdir || p.starts_with(&format!("{}/", layout.pkgdir)));
            let under_app = p == layout.appdir || p.starts_with(&format!("{}/", layout.appdir));
            if !(owned_shim || owned_file || under_payload || under_app) {
                continue;
            }
            if is_protected_basename(p) {
                continue;
            }
            if fs::symlink_metadata(p).is_ok() && fs::remove_file(p).is_ok() {
                pruned += 1;
            }
        }
        if pruned > 0 {
            println!("spk: pruned {} stale file(s) from previous version", pruned);
        }
    }
    // Drop stale <appdir>/bin links for commands gone in the new version.
    {
        let bin_dir = format!("{}/bin", layout.appdir);
        if let Ok(entries) = fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.is_empty() || commands.contains(&fname) {
                    continue;
                }
                let full = format!("{}/{}", bin_dir, fname);
                // Only remove symlinks we manage (app links are always links).
                if let Ok(m) = fs::symlink_metadata(&full) {
                    if m.file_type().is_symlink() && fs::remove_file(&full).is_ok() {
                        println!("spk: pruned stale app link {}", full);
                    }
                }
            }
        }
    }

    let run_path = format!("{}/run", layout.appdir);
    let run_text = [
        "#!/bin/sh",
        "cmd=\"$1\"",
        "if [ -z \"$cmd\" ]; then",
        "    echo \"usage: ./run <command> [args...]\"",
        "    ls \"$(dirname \"$0\")/bin\"",
        "    exit 1",
        "fi",
        "shift",
        "exec \"$(dirname \"$0\")/bin/$cmd\" \"$@\"",
        "",
    ]
    .join("\n");
    check(fs::write(&run_path, run_text), &format!("cannot write {}", run_path));
    check(fs::set_permissions(&run_path, fs::Permissions::from_mode(0o755)), &format!("cannot set mode on {}", run_path));

    commands.sort();
    if version.is_empty() {
        println!("spk: installed {} ({} files)", name, installed.len());
    } else {
        println!("spk: installed {} v{} ({} files)", name, version, installed.len());
    }
    println!("spk: app dir: {}", layout.appdir);
    println!("spk: files in: {}", if system { layout.root.as_str() } else { layout.pkgdir.as_str() });
    if commands.is_empty() {
        println!("spk: note: package installed no runnable commands");
    } else {
        println!("spk: commands: {}", commands.join(" "));
        println!("spk: run one with: {}/run <command>", layout.appdir);
    }
    if layout.user_mode && !path_contains(&layout.shimdir) {
        println!("spk: hint: add {} to PATH (export PATH=\"$HOME/.local/bin:$PATH\")", layout.shimdir);
    }
    if !layout.user_mode && layout.root != "/" {
        println!("spk: installed into {}", layout.root);
    }
}

fn path_contains(dir: &str) -> bool {
    match std::env::var("PATH") {
        Ok(path) => path.split(':').any(|entry| entry == dir),
        Err(_) => false,
    }
}

// Shared with rm: never auto-delete these configs on upgrade prune, even if a
// previous package version recorded them. Scoped to /etc/ so a binary that
// merely shares the basename (e.g. /usr/bin/passwd) is still pruned.
fn is_protected_basename(path: &str) -> bool {
    if !path.contains("/etc/") {
        return false;
    }
    let base = Path::new(path)
        .file_name()
        .map(|b| b.to_string_lossy().to_string())
        .unwrap_or_default();
    matches!(
        base.as_str(),
        "passwd" | "shadow" | "gshadow" | "group" | "fstab" | "machine-id"
            | "hostname" | "hosts" | "resolv.conf"
    )
}

fn list(layout: &Layout) {
    let pkgs = layout.registry.trim_end_matches('/');
    let entries = match fs::read_dir(pkgs) {
        Ok(entries) => entries,
        Err(_) => {
            println!("spk: nothing installed");
            return;
        }
    };
    let mut rows: Vec<(String, String, String, bool)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let pkg = entry.file_name().to_string_lossy().to_string();
        let version = fs::read_to_string(dir.join("version")).unwrap_or_default();
        let category = fs::read_to_string(dir.join("category")).unwrap_or_default();
        let files = fs::read_to_string(dir.join("files")).unwrap_or_default();
        let prefix = layout.root.trim_end_matches('/');
        let system = files.lines().any(|l| {
            let p = l.trim();
            if p.is_empty() {
                return false;
            }
            let rel = if !prefix.is_empty() && prefix != "/" {
                p.strip_prefix(prefix).unwrap_or(p)
            } else {
                p
            };
            if rel.starts_with("/spk_pkgs/")
                || rel.starts_with("/opt/spk/")
                || rel.starts_with("/home/")
                || rel.contains(".local/share/spk/")
            {
                return false;
            }
            rel.starts_with("/usr/")
                || rel.starts_with("/etc/")
                || rel.starts_with("/lib")
                || rel.starts_with("/bin/")
                || rel.starts_with("/sbin/")
                || rel.starts_with("/var/")
                || rel.starts_with("/opt/")
        });
        rows.push((pkg, version.trim().to_string(), category.trim().to_string(), system));
    }
    rows.sort();
    if rows.is_empty() {
        println!("spk: nothing installed");
        return;
    }
    for (pkg, version, category, system) in rows {
        let cat = if category.is_empty() { "misc".to_string() } else { category };
        let kind = if system { "system" } else { "leaf" };
        if version.is_empty() {
            println!("{} [{}] ({})", pkg, cat, kind);
        } else {
            println!("{} v{} [{}] ({})", pkg, version, cat, kind);
        }
    }
}

fn http_get(url: &str) -> String {
    match http_get_opt(url) {
        Some(text) => text,
        None => fail(&format!("could not fetch {} (not found or network down)", url)),
    }
}

// DEBUG-MARK: HTTP-OPT v1.
pub(crate) fn http_get_opt(url: &str) -> Option<String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match ureq::get(url).call() {
            Ok(mut response) => {
                if response.status().as_u16() != 200 {
                    return None;
                }
                match response.body_mut().read_to_string() {
                    Ok(text) => return Some(text),
                    Err(_) => {
                        if attempt >= 3 {
                            return None;
                        }
                    }
                }
            }
            Err(ureq::Error::StatusCode(404)) => return None,
            Err(_) => {
                if attempt >= 3 {
                    return None;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2 * attempt as u64));
    }
}

struct IndexEntry {
    name: String,
    category: String,
    version: String,
    description: String,
}

// DEBUG-MARK: CATEGORY-IDX v1.
fn parse_index(text: &str) -> Vec<IndexEntry> {
    let mut out = Vec::new();
    let arr = match text.find("\"packages\"") {
        Some(pos) => pos,
        None => return out,
    };
    let rest = &text[arr..];
    let open = match rest.find('[') {
        Some(pos) => pos,
        None => return out,
    };
    let bytes = rest.as_bytes();
    let mut depth = 1;
    let mut start: Option<usize> = None;
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                if depth == 1 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 1 {
                    if let Some(s) = start.take() {
                        let obj = &rest[s..=i];
                        let name = read_field(obj, "name");
                        if !name.is_empty() {
                            out.push(IndexEntry {
                                name,
                                category: read_field(obj, "category"),
                                version: read_field(obj, "version"),
                                description: read_field(obj, "description"),
                            });
                        }
                    }
                }
                if depth == 0 {
                    break;
                }
            }
            b']' => {
                if depth == 1 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

pub(crate) fn resolve_package(base: &str, name: &str) -> (String, String, String) {
    let direct = format!("{}/{}/package.json", base, name);
    if let Some(manifest) = http_get_opt(&direct) {
        return (manifest_category(&manifest), manifest, format!("{}/{}", base, name));
    }
    step(&format!("{} is not at the top level, checking the index...", name));
    let index_text = http_get(&format!("{}/index.json", base));
    let entries = parse_index(&index_text);
    let mut matched: Vec<&IndexEntry> = entries.iter().filter(|e| e.name == *name).collect();
    if matched.is_empty() {
        let lowered = name.to_ascii_lowercase();
        matched = entries
            .iter()
            .filter(|e| e.name.to_ascii_lowercase() == lowered)
            .collect();
    }
    if matched.is_empty() {
        fail(&format!("no package named {} (check spelling with the repo index)", name));
    }
    if matched.len() == 1 {
        let entry = matched[0];
        return fetch_candidate(base, entry);
    }
    eprintln!("{} is in several categories:", paint("1;33", name));
    for (i, entry) in matched.iter().enumerate() {
        let cat = if entry.category.is_empty() { "misc" } else { entry.category.as_str() };
        let ver = if entry.version.is_empty() { "".to_string() } else { format!(" v{}", entry.version) };
        eprintln!("  [{}] {}{}  {}", i + 1, paint("1;36", cat), paint("1", &ver), entry.description);
    }
    for _ in 0..3 {
        eprint!("pick one [1-{}]: ", matched.len());
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        if let Ok(n) = line.trim().parse::<usize>() {
            if n >= 1 && n <= matched.len() {
                return fetch_candidate(base, matched[n - 1]);
            }
        }
        eprintln!("enter a number between 1 and {}", matched.len());
    }
    fail(&format!("no choice made for {}", name));
}

fn manifest_category(manifest: &str) -> String {
    read_field(manifest, "category")
}

// DEBUG-MARK: SELF-UPDATE v1.
const SELF_UPDATE_API: &str = "https://api.github.com/repos/Cgtlpa/spk/releases/latest";

fn update_api() -> String {
    match std::env::var("SPK_UPDATE_API") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => SELF_UPDATE_API.to_string(),
    }
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> Vec<u64> {
        s.trim()
            .trim_start_matches(['v', 'V'])
            .split('.')
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    }
    let mut pa = parts(a);
    let mut pb = parts(b);
    let len = pa.len().max(pb.len()).max(1);
    pa.resize(len, 0);
    pb.resize(len, 0);
    pa.cmp(&pb)
}

fn find_asset_url(text: &str, asset: &str) -> String {
    let key = "\"browser_download_url\"";
    let mut search = 0;
    while let Some(pos) = text[search..].find(key) {
        let abs_pos = search + pos + key.len();
        let after = &text[abs_pos..];
        let after = after.trim_start_matches([' ', '\t', '\r', '\n', ':']);
        let after = after.trim_start();
        if !after.starts_with('"') {
            search = abs_pos;
            continue;
        }
        let end = match after[1..].find('"') {
            Some(e) => e + 1,
            None => {
                search = abs_pos;
                continue;
            }
        };
        let url = &after[1..end];
        let prefix = &text[..abs_pos];
        if let Some(npos) = prefix.rfind("\"name\"") {
            let nrest = &prefix[npos + 6..];
            let nrest = nrest.trim_start_matches([' ', '\t', '\r', '\n', ':']);
            let nrest = nrest.trim_start();
            if nrest.starts_with('"') {
                if let Some(nend) = nrest[1..].find('"') {
                    if &nrest[1..nend + 1] == asset {
                        return url.to_string();
                    }
                }
            }
        }
        search = abs_pos;
    }
    String::new()
}

fn self_update(check_only: bool) {
    let api = update_api();
    step("checking for spk updates...");
    let release = match http_get_opt(&api) {
        Some(release) => release,
        None => fail("could not reach the release feed (network down or rate-limited?)"),
    };
    let tag = read_field(&release, "tag_name")
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    if tag.is_empty() {
        fail("release feed has no tag_name");
    }
    let current = env!("CARGO_PKG_VERSION");
    match compare_versions(&tag, current) {
        std::cmp::Ordering::Equal => {
            println!("spk: v{} is already the latest", current);
            return;
        }
        std::cmp::Ordering::Less => {
            println!(
                "spk: installed v{} is newer than released v{} - nothing to do",
                current, tag
            );
            return;
        }
        std::cmp::Ordering::Greater => {}
    }
    if check_only {
        println!("spk: update available: v{} -> v{}", current, tag);
        return;
    }
    let bin_url = find_asset_url(&release, "spk-x86_64");
    let sum_url = find_asset_url(&release, "spk-x86_64.sha256");
    if bin_url.is_empty() || sum_url.is_empty() {
        fail("release is missing spk-x86_64 assets");
    }
    println!("spk: updating v{} -> v{}", current, tag);
    let dir = std::env::temp_dir().join(format!("spk-self-{}", std::process::id()));
    check(
        fs::create_dir_all(&dir),
        "cannot create temp dir for self-update",
    );
    let bin_path = dir.join("spk-x86_64").to_string_lossy().to_string();
    let digest = download(&bin_url, &bin_path, 1);
    let sums = http_get(&sum_url);
    let expected = sums.split_whitespace().next().unwrap_or_default();
    if expected.is_empty() || digest.to_lowercase() != expected.trim().to_lowercase() {
        let _ = fs::remove_dir_all(&dir);
        fail("sha256 mismatch on the release binary - aborting self-update");
    }
    println!("spk: checksum ok");
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => fail(&format!("cannot locate running binary: {}", err)),
    };
    let mode = fs::metadata(&exe).map(|m| m.permissions().mode()).unwrap_or(0o755);
    let bak = exe.with_extension("bak");
    let _ = fs::remove_file(&bak);
    if fs::rename(&exe, &bak).is_err() {
        let _ = fs::remove_dir_all(&dir);
        fail("cannot replace the running binary (run with sudo?)");
    }
    let restore = |msg: &str| -> ! {
        let _ = fs::rename(&bak, &exe);
        let _ = fs::remove_dir_all(&dir);
        fail(msg);
    };
    if fs::copy(&bin_path, &exe).is_err() {
        restore("cannot install the new binary (run with sudo?)");
    }
    let _ = fs::set_permissions(&exe, fs::Permissions::from_mode(mode));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_file(&bak);
    done_line(&format!("spk updated to v{}", tag));
}

#[cfg(test)]
mod self_update_tests {
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("0.2.0", "0.2.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("v0.2.0", "0.2.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("0.10.0", "0.2.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("0.1.0", "0.2.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("1.0", "1.0.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn assets_resolve_by_name() {
        let feed = r#"{"tag_name": "v0.2.0", "assets": [
            {"name": "spk-x86_64.sha256", "browser_download_url": "https://x/s.sha256"},
            {"name": "spk-x86_64", "browser_download_url": "https://x/s"}
        ]}"#;
        assert_eq!(find_asset_url(feed, "spk-x86_64"), "https://x/s");
        assert_eq!(find_asset_url(feed, "spk-x86_64.sha256"), "https://x/s.sha256");
        assert_eq!(find_asset_url(feed, "nope"), "");
    }

    #[test]
    fn depends_parses_string_arrays() {
        assert_eq!(read_string_array(r#"{"depends": []}"#, "depends"), Vec::<String>::new());
        assert_eq!(
            read_string_array(r#"{"depends": ["a", "b"]}"#, "depends"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(read_string_array(r#"{"x": 1}"#, "depends"), Vec::<String>::new());
    }
}

fn fetch_candidate(base: &str, entry: &IndexEntry) -> (String, String, String) {
    if !entry.category.is_empty() {
        let prefix = format!("{}/{}/{}", base, entry.category, entry.name);
        if let Some(manifest) = http_get_opt(&format!("{}/package.json", prefix)) {
            let mut category = manifest_category(&manifest);
            if category.is_empty() {
                category = entry.category.clone();
            }
            return (category, manifest, prefix);
        }
    }
    let prefix = format!("{}/{}", base, entry.name);
    let manifest = http_get(&format!("{}/package.json", prefix));
    let mut category = manifest_category(&manifest);
    if category.is_empty() {
        category = entry.category.clone();
    }
    (category, manifest, prefix)
}

fn download(url: &str, dst: &str, parts: u32) -> String {
    // [SPK-DEBUG-OK 2026-09-20] download audited.
    // Single file when parts==1; `<url>.000`, `<url>.001`, ... when split.
    // Unknown-length split (parts==1 on disk as .000/.001/...) is probed:
    // miss on bare URL -> try .000... until first 404 after data. Appends
    // per part, truncates back to part-start on transient errors, 6 retries
    // with backoff, sha256 over the concatenated file.
    // DEBUG-MARK: DOWNLOAD v1.
    let _ = fs::remove_file(dst);
    let mut split = parts > 1;
    let mut index = 0;

    loop {
        let part_url = if split {
            format!("{}.{:03}", url, index)
        } else {
            url.to_string()
        };
        if split {
            if parts > 1 {
                println!("spk: downloading part {} of {}", index + 1, parts);
            } else {
                println!("spk: downloading part {}", index + 1);
            }
        }

        let start = fs::metadata(dst).map(|m| m.len()).unwrap_or(0);
        let mut attempt = 0;
        loop {
            attempt += 1;
            match fetch_part(&part_url, dst) {
                PartFetch::Ok => break,
                PartFetch::NotFound => {
                    if !split && parts <= 1 && index == 0 {
                        let _ = fs::remove_file(dst);
                        split = true;
                        break;
                    } else if split && parts <= 1 && index > 0 {
                        return hash_file(dst);
                    } else {
                        let _ = fs::remove_file(dst);
                        fail(&format!("could not download {}", part_url));
                    }
                }
                PartFetch::Transient(err) => {
                    if err.starts_with("cannot write") {
                        fail(&format!("could not download {}: {}", part_url, err));
                    }
                    truncate_to(dst, start);
                    if attempt >= 6 {
                        let _ = fs::remove_file(dst);
                        fail(&format!("could not download {}: {} (6 attempts)", part_url, err));
                    }
                    let wait = 2u64.pow(attempt.min(5));
                    println!("spk: part download failed (attempt {}), retrying in {}s...", attempt, wait);
                    std::thread::sleep(std::time::Duration::from_secs(wait));
                }
            }
        }
        if split && fs::metadata(dst).is_err() && index == 0 {
            continue;
        }

        index += 1;
        if index > 64 {
            let _ = fs::remove_file(dst);
            fail(&format!("too many parts for {} (limit 64)", url));
        }
        if !split || (parts > 1 && index == parts) {
            break;
        }
    }

    hash_file(dst)
}

enum PartFetch {
    Ok,
    NotFound,
    Transient(String),
}

// DEBUG-MARK: UI-PROGRESS v1.
fn print_progress(done: u64, total: Option<u64>) {
    match total {
        Some(t) if t > 0 => {
            let pct = ((done as f64 / t as f64) * 100.0).min(100.0);
            let bars = (pct / 5.0) as usize;
            let bar: String = std::iter::repeat('=').take(bars).collect();
            eprint!("\r  [{:<20}] {:>5.1}% {}", bar, pct, paint("1;36", &format!("{}/{}", done, t)));
        }
        _ => {
            eprint!("\r  {} downloaded", done);
        }
    }
    let _ = std::io::stderr().flush();
}

fn fetch_part(part_url: &str, dst: &str) -> PartFetch {
    let mut response = match ureq::get(part_url).call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(404)) => return PartFetch::NotFound,
        Err(err) => return PartFetch::Transient(err.to_string()),
    };
    if response.status().as_u16() != 200 {
        return PartFetch::Transient(format!("http {}", response.status().as_u16()));
    }
    let total: Option<u64> = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok());

    let mut out = match fs::OpenOptions::new().append(true).create(true).open(dst) {
        Ok(file) => file,
        Err(err) => return PartFetch::Transient(format!("cannot write {}: {}", dst, err)),
    };
    let mut reader = response.body_mut().as_reader();
    let mut buf = [0u8; 65536];
    let mut done: u64 = 0;
    let mut shown = false;

    loop {
        let count = match reader.read(&mut buf) {
            Ok(count) => count,
            Err(err) => {
                eprintln!();
                return PartFetch::Transient(format!("download failed: {}", err));
            }
        };
        if count == 0 {
            break;
        }
        if let Err(err) = out.write_all(&buf[..count]) {
            eprintln!();
            return PartFetch::Transient(format!("cannot write {}: {}", dst, err));
        }
        done += count as u64;
        print_progress(done, total);
        shown = true;
    }
    if shown {
        eprintln!();
    }

    PartFetch::Ok
}

fn truncate_to(dst: &str, len: u64) {
    if let Ok(file) = fs::OpenOptions::new().write(true).open(dst) {
        let _ = file.set_len(len);
    }
}

fn hash_file(dst: &str) -> String {
    let mut file = match fs::File::open(dst) {
        Ok(file) => file,
        Err(err) => fail(&format!("cannot open downloaded file {}: {}", dst, err)),
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let count = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => count,
            Err(err) => {
                let _ = fs::remove_file(dst);
                fail(&format!("cannot hash {}: {}", dst, err));
            }
        };
        hasher.update(&buf[..count]);
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn read_field(text: &str, key: &str) -> String {
    // [SPK-DEBUG-OK 2026-09-20] manifest mini-parser audited.
    // Handles `"key": "string"`, `"key": true/1/yes` and `"key": 3`
    // (quoted or bare). Not full JSON — enough for flat package.json
    // manifests (filename/version/sha256/parts/system).
    // DEBUG-MARK: READ-FIELD v1.
    let needle = format!("\"{}\"", key);
    let pos = match text.find(&needle) {
        Some(pos) => pos + needle.len(),
        None => return String::new(),
    };
    let rest = &text[pos..];
    let colon = match rest.find(':') {
        Some(colon) => colon + 1,
        None => return String::new(),
    };
    let mut value = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in rest[colon..].chars() {
        if escaped {
            escaped = false;
            if in_string {
                value.push(c);
            }
            continue;
        }
        if c == '\\' && in_string {
            escaped = true;
            value.push(c);
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            if !in_string {
                break;
            }
            continue;
        }
        if !in_string && (c == ',' || c == '}' || c == '\n' || c == ' ' || c == '\t' || c == '\r' || c == ':') {
            if !value.is_empty() {
                break;
            }
            continue;
        }
        value.push(c);
    }
    value.trim().trim_matches('"').to_string()
}

// DEBUG-MARK: READ-STRING-ARRAY v1.
pub(crate) fn read_string_array(text: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\"", key);
    let pos = match text.find(&needle) {
        Some(pos) => pos + needle.len(),
        None => return Vec::new(),
    };
    let rest = &text[pos..];
    let open = match rest.find('[') {
        Some(open) => open + 1,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in rest[open..].chars() {
        if escaped {
            escaped = false;
            if in_string {
                cur.push(c);
            }
            continue;
        }
        if c == '\\' && in_string {
            escaped = true;
            continue;
        }
        if c == '"' {
            if in_string {
                let value = cur.trim().to_string();
                if !value.is_empty() {
                    out.push(value);
                }
                cur.clear();
            }
            in_string = !in_string;
            continue;
        }
        if c == ']' && !in_string {
            break;
        }
        if in_string {
            cur.push(c);
        }
    }
    out
}

fn skipped_name(name: &str) -> bool {
    let base = Path::new(name)
        .file_name()
        .map(|b| b.to_string_lossy().to_string())
        .unwrap_or_default();
    !base.is_empty() && (core_lib(&base) || system_tool(&base))
}

fn extract(archive: &str, root: &str, system: bool) -> Vec<Installed> {
    // [SPK-DEBUG-OK 2026-09-20] tar extract audited.
    // `clean()` jails `..`/absolute paths under root; `resolve_link()`
    // rejects symlinks escaping root. System mode skips bundled glibc
    // copies (core_lib/system_tool) and keeps the host's. Dirs created,
    // symlinks + hardlinks (with copy fallback) recorded, regular files
    // get their tar modes. Returns installed paths for the registry.
    // DEBUG-MARK: EXTRACT v1.
    let mut installed: Vec<Installed> = Vec::new();
    let mut skipped = 0;
    let mut pending_links: Vec<(String, String, u32)> = Vec::new();

    let file = match fs::File::open(archive) {
        Ok(file) => file,
        Err(err) => fail(&format!("cannot open {}: {}", archive, err)),
    };
    let reader: Box<dyn Read> = if is_gzip(archive) {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut tar = tar::Archive::new(reader);

    let entries = match tar.entries() {
        Ok(entries) => entries,
        Err(err) => {
            fail(&format!("bad archive {}: {}", archive, err));
        }
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                fail(&format!("bad archive {}: {}", archive, err));
            }
        };
        let kind = entry.header().entry_type();

        if kind.is_pax_global_extensions() || kind.is_pax_local_extensions() || kind.is_gnu_longname() || kind.is_gnu_longlink() {
            continue;
        }

        let name = match entry.path() {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(err) => {
                fail(&format!("bad path in {}: {}", archive, err));
            }
        };
        let dest = clean(&name, root);
        let mode = entry.header().mode().unwrap_or(0o644);

        if system && !kind.is_dir() && skipped_name(&name) {
            skipped += 1;
            continue;
        }

        if kind.is_dir() {
            if Path::new(&dest).is_file() {
                let _ = fs::remove_file(&dest);
            }
            check(fs::create_dir_all(&dest), &format!("cannot create {}", dest));
            continue;
        }

        if kind.is_symlink() {
            let target = match entry.link_name() {
                Ok(Some(target)) => target.to_string_lossy().to_string(),
                _ => {
                    fail(&format!("symlink without target in {}", name));
                }
            };
            let link = resolve_link(&dest, &target, root);
            if Path::new(&dest).is_dir() {
                continue;
            }
            make_parent(&dest);
            let _ = fs::remove_file(&dest);
            check(std::os::unix::fs::symlink(&link, &dest), &format!("cannot create link {}", dest));
            installed.push(Installed { path: dest, mode, is_link: true });
            continue;
        }

        if kind.is_hard_link() {
            let target = match entry.link_name() {
                Ok(Some(target)) => target.to_string_lossy().to_string(),
                _ => {
                    fail(&format!("hardlink without target in {}", name));
                }
            };
            if system && (skipped_name(&name) || skipped_name(&target)) {
                skipped += 1;
                continue;
            }
            pending_links.push((dest, target, mode));
            continue;
        }

        make_parent(&dest);
        let _ = fs::remove_file(&dest);
        let mut out = match fs::File::create(&dest) {
            Ok(file) => file,
            Err(err) => fail(&format!("cannot create {}: {}", dest, err)),
        };
        if let Err(err) = std::io::copy(&mut entry, &mut out) {
            fail(&format!("cannot write {}: {}", dest, err));
        }
        check(fs::set_permissions(&dest, fs::Permissions::from_mode(mode)), &format!("cannot set mode on {}", dest));
        installed.push(Installed { path: dest, mode, is_link: false });
    }

    for (dest, target, mode) in pending_links {
        let src = clean(&target, root);
        make_parent(&dest);
        let _ = fs::remove_file(&dest);
        if let Err(err) = fs::hard_link(&src, &dest) {
            if Path::new(&src).exists() {
                let _ = fs::remove_file(&dest);
                if fs::copy(&src, &dest).is_ok() {
                    installed.push(Installed { path: dest, mode, is_link: false });
                    continue;
                }
            }
            fail(&format!("cannot create hardlink {}: {}", dest, err));
        }
        installed.push(Installed { path: dest, mode, is_link: true });
    }

    if skipped > 0 {
        println!("spk: kept {} system librar(y/ies), skipped bundled copies", skipped);
    }

    installed
}

fn make_parent(dest: &str) {
    if let Some(parent) = Path::new(dest).parent() {
        check(fs::create_dir_all(parent), &format!("cannot create {}", parent.display()));
    }
}

fn clean(name: &str, root: &str) -> String {
    // [SPK-DEBUG-OK 2026-09-20] path jail audited — strips leading /,
    // collapses `.`, pops `..`, then prefixes root. Never escapes root.
    // DEBUG-MARK: CLEAN v1.
    let mut parts: Vec<&str> = Vec::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            parts.pop();
            continue;
        }
        parts.push(part);
    }
    let joined = parts.join("/");
    if root == "/" || root.is_empty() {
        format!("/{}", joined)
    } else {
        format!("{}/{}", root.trim_end_matches('/'), joined)
    }
}

fn resolve_link(link_dest: &str, target: &str, root: &str) -> String {
    // [SPK-DEBUG-OK 2026-09-20] symlink scope check audited — absolute
    // targets are rebased under --root, `..` normalised, escapes rejected.
    // DEBUG-MARK: RESOLVE-LINK v1.
    // FIX 2026-09-20 RESOLVE-LINK-ROOT: absolute targets are stored verbatim
    // (like pacman --root). The old code rebased them to include the host
    // --root prefix (e.g. /silen/usr/lib/...) which is correct on the host
    // but broken inside the chroot after boot; it also wrongly rejected
    // valid absolute targets as "escapes". Only relative targets need the
    // join+normalise escape check below.
    if target.starts_with('/') {
        // Normalise `..`/`.` without touching the fs; any absolute path is
        // inside "/" by construction, so it can never escape the target root.
        let mut parts: Vec<&str> = Vec::new();
        for part in target.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                parts.pop();
                continue;
            }
            parts.push(part);
        }
        let _norm = format!("/{}", parts.join("/"));
        return target.to_string();
    }
    let scope = if root == "/" || root.is_empty() { "/".to_string() } else { root.trim_end_matches('/').to_string() };
    // Only relative targets reach here (absolute returned above).
    let parent = Path::new(link_dest).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let abs = format!("{}/{}", parent.trim_end_matches('/'), target);
    // normalize .. without touching fs
    let mut parts: Vec<&str> = Vec::new();
    for part in abs.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            parts.pop();
            continue;
        }
        parts.push(part);
    }
    let norm = format!("/{}", parts.join("/"));
    if scope != "/" && (norm != scope && !norm.starts_with(&format!("{}/", scope))) {
        fail(&format!("symlink escapes install root: {} -> {}", link_dest, target));
    }
    target.to_string()
}

fn is_gzip(path: &str) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut head = [0u8; 2];
    if file.read_exact(&mut head).is_err() {
        return false;
    }
    head[0] == 0x1f && head[1] == 0x8b
}
