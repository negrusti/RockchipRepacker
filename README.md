# rkimg

Minimal Rockchip image pack/unpack utility in C with a cross-platform CLI.

This implements a small, practical subset of Rockchip firmware image handling:

- unpack `RKFW` firmware images
- pack `RKFW` firmware images
- unpack standalone `RKAF` update images
- pack standalone `RKAF` update images
- unpack nested `RKAF` payloads found inside `RKFW`
- rebuild nested `RKAF` payloads during `RKFW` packing

It is intentionally narrow. Broader second-layer format handling is not
implemented here.

## Build

### Linux or macOS

```sh
make
```

### Cross-platform with CMake

```sh
cmake -S . -B build
cmake --build build
```

## Releases

GitHub Actions builds release archives for Linux and Windows.

- pushes and pull requests validate the build
- pushing a tag like `v1.0.0` publishes a GitHub Release with packaged binaries

## Usage

Linux or macOS:

```sh
./rkimg unpack input.img outdir
./rkimg pack outdir rebuilt.img
```

Windows:

```powershell
.\build\Debug\rkimg.exe unpack input.img outdir
.\build\Debug\rkimg.exe pack outdir rebuilt.img
```

## Unpack Layout

For `RKFW` images:

```text
outdir/
  manifest.ini
  loader.bin
  update.img
  update/
    manifest.ini
    files/...
```

For standalone `RKAF` images:

```text
outdir/
  manifest.ini
  files/...
```

## Manifest Notes

`manifest.ini` stores only the fields needed for minimal round-tripping.

- `RKFW` manifests include timestamp/header fields plus `loader_file`,
  `update_file`, `append_md5`, and optional `update_dir` when the payload was
  unpacked as nested `RKAF`.
- `RKAF` manifests include image metadata plus `[entryN]` sections for each
  file table entry.

## Limitations

- `SELF` entries are rejected on pack. Those images need extra handling that
  this minimal utility does not currently replicate.
- `RESERVED` entries are preserved as metadata-only table entries.
- Extracted file payloads are written as stored in the image.
- Checksum mismatches during unpack are warnings, not hard failures.
