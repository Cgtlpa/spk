# spk releases — Silen Linux package manager (spark)

This repo holds only release binaries. The source lives in
[Cgtlpa/SilenLinux](https://github.com/Cgtlpa/SilenLinux) under `spk/`.

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

## Release

1. Change and test the source in SilenLinux (`cargo check`, `cargo clippy`,
   `cargo test` in `spk/`), bump `version` in `spk/Cargo.toml`.
2. Tag `vX.Y.Z` here — CI checks the tag out of SilenLinux's `spk/`,
   refuses on version mismatch, builds the release binary and attaches
   `spk-x86_64` + `spk-x86_64.sha256` to the GitHub release.
3. `spk self-update` picks it up (tag without the `v` is compared
   against `spk --version`).
