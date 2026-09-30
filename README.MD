# Read Only File System Extractor

RofsExtractor is a command-line utility for listing and extracting files from Symbian ROM images and raw firmware dumps. It supports ordinary bare ROM images, embedded ROM images, NAND dumps with out-of-band data, and raw NOR dumps whose physical regions use different runtime address mappings.

## Features

- List the complete Symbian ROM directory tree without extracting files.
- Extract all files or only paths matching a case-insensitive substring.
- Read plain and EPOC loader-wrapped ROM images.
- Scan a larger firmware file for an embedded Symbian ROM image.
- Decode uncompressed and BytePair-compressed demand-paged ROM data.
- Strip interleaved NAND OOB data before parsing the ROM.
- Automatically reconstruct multi-region virtual-to-physical mappings in supported raw NOR dumps.
- Preserve the ROM directory structure and include the ROM image header when extracting executables and DLLs.

## Requirements

- Python 3.10 or newer
- No third-party Python packages

## Usage

Display all available commands:

```bash
python3 RofsExtractor.py --help
```

List the files and directories in a ROM image:

```bash
python3 RofsExtractor.py list rom.bin
```

Extract the complete ROM image to the default `extracted` directory:

```bash
python3 RofsExtractor.py extract rom.bin
```

Choose a different output directory:

```bash
python3 RofsExtractor.py extract rom.bin --output rom_extracted
```

Extract only paths containing a particular string:

```bash
python3 RofsExtractor.py extract rom.bin \
  --pattern sys/bin \
  --output system_binaries
```

The `--pattern` comparison is case-insensitive and is applied to the complete path stored in the ROM.

Use `--help` with `list` or `extract` for all available options.

## Image Workflows

### 1. Plain Bare ROM

If the ROM header begins at offset zero, no additional options are required:

```bash
python3 RofsExtractor.py list rom.bin
python3 RofsExtractor.py extract rom.bin --output extracted
```

### 2. Embedded ROM

If the exact ROM offset is known, pass it as a decimal or `0x`-prefixed hexadecimal value:

```bash
python3 RofsExtractor.py extract firmware.bin \
  --offset 0x40000 \
  --output extracted
```

If the offset is unknown, use the heuristic scanner:

```bash
python3 RofsExtractor.py extract firmware.bin \
  --scan \
  --output extracted
```

Scanning checks candidate ROM headers and selects the candidate with the most plausible directory tree.

### 3. Raw NOR Dump

Raw NOR dumps may contain several physical regions whose directory entries refer to different runtime virtual address ranges. The tool detects these mappings from valid ROM-resident E32 executable headers, locates the root directory, and joins files that cross mapping boundaries.

No manual mapping options are required:

```bash
python3 RofsExtractor.py list dump_nor.bin
python3 RofsExtractor.py extract dump_nor.bin --output extracted
```

When detection succeeds, the first line of `list` output shows the root directory offset and the recovered mappings.

### 4. NAND Dump with OOB Data

For a raw NAND dump containing interleaved page data and spare/OOB bytes, specify both sizes. For example, to keep 512 data bytes and discard 16 OOB bytes from every physical page:

```bash
python3 RofsExtractor.py extract dump_nand.bin \
  --nand-page-size 512 \
  --nand-oob-size 16 \
  --scan \
  --output extracted
```

`--nand-page-size` and `--nand-oob-size` must always be used together. These options only remove OOB bytes; they do not reconstruct an FTL or correct NAND ECC errors.

### 5. Damaged BytePair Pages

By default, extraction stops when a corrupt BytePair-compressed page is encountered. To continue recovery, replace each corrupt page with zeroes:

```bash
python3 RofsExtractor.py extract rom.bin \
  --ignore-corrupt-pages \
  --output recovered
```

The tool prints a warning for every substituted page. Files using those pages may be incomplete or unusable.

## Warning

Treat extracted files as recovery output until they have been validated. Heuristic scanning and raw NOR mapping detection depend on consistent headers and directory metadata; damaged or partial dumps may produce missing files or fail detection.

`--ignore-corrupt-pages` deliberately replaces unreadable data with zeroes. It is useful for best-effort recovery, but it does not repair the affected executable or resource data.
