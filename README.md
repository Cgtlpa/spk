# spk — Silen Linux package manager (spark)

`spk` installs system packages straight into `/` (kernels, drivers, desktops,
display managers) and leaf apps isolated with shims, plus automatic
dependency installs via each manifest's `depends` list.

## Install / update

On a Silen system with any spk from v0.2.0 on:

```sh
sudo spk self-update          # replace /usr/bin/spk with the latest release
sudo spk self-update --check  # only report
```

Manual first install:

```sh
curl -sSL -o spk https://github.com/Cgtlpa/spk/releases/latest/download/spk-x86_64
echo "$(curl -sSL https://github.com/Cgtlpa/spk/releases/latest/download/spk-x86_64.sha256)  spk" | sha256sum -c -
sudo install -m0755 spk /usr/bin/spk
```

## Develop

Canonical source lives in the SilenLinux repo under `spk/`; this repo
mirrors it for releases. Sync with:

```sh
cp -r ../SilenLinux/spk/src ../SilenLinux/spk/Cargo.toml ../SilenLinux/spk/Cargo.lock .
```

Then `cargo check`, `cargo clippy`, `cargo test`.

## Release

1. Bump `version` in `Cargo.toml` (and in SilenLinux).
2. Commit, tag `vX.Y.Z`, push the tag — CI builds the release binary
   and attaches `spk-x86_64` + `spk-x86_64.sha256` to the GitHub release.
3. `spk self-update` picks it up (tag without the `v` is compared
   against `spk --version`).
