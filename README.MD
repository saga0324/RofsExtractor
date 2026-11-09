# Read Only File System Extractor

RofsExtractor is a command-line utility for listing and extracting files from Symbian ARM ROM, ROFS, and ROFx images. It can read images at a known offset, scan larger firmware dumps for an embedded image, and strip interleaved NAND out-of-band (OOB) data before parsing.

## Features

- List ROM, ROFS, and ROFx directory entries without extracting files.
- Extract all files or only paths matching a case-insensitive substring.
- Read plain ARM ROM images and ROFS/ROFx images.
- Scan a larger firmware file for an embedded ROM/ROFS/ROFx image.
- Decode uncompressed and BytePair-compressed demand-paged ROM data.
- Strip interleaved NAND OOB data before parsing the ROM.
- Select a ROM hardware variant when the image contains multiple root directories.
- Preserve directories, including empty directories when included in the selection.
- Include recognized ROM executable/DLL module headers in extracted files.
- Validate output paths and escape filenames that are incompatible with Windows.

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

Extract all files to the default `rofs_extracted` directory:

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

The `--pattern` comparison is case-insensitive and is applied to the complete image path. It filters directory entries as well as files; parent directories needed for matching files are still created.

Use `--help` with `list` or `extract` for all available options.

## Image Workflows

### 1. Plain ROM, ROFS, or ROFx

If the image header begins at offset zero, no additional options are required. The format is detected automatically:

```bash
python3 RofsExtractor.py list rom.bin
python3 RofsExtractor.py extract rom.bin --output extracted
python3 RofsExtractor.py extract rofs.bin --output rofs_extracted
```

### 2. Embedded Image

If the exact header offset is known, pass it as a decimal or `0x`-prefixed hexadecimal value:

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

Scanning validates candidate headers and directory trees, samples file data, and selects the highest-scoring image. It selects one image per invocation, rather than extracting every image in a dump. With `--scan`, `--offset` is not used.

### 3. ROM Hardware Variants

ROM images with a single root variant are selected automatically. If multiple variants exist, specify the hardware variant ID:

```bash
python3 RofsExtractor.py list rom.bin --variant 0x12345678
python3 RofsExtractor.py extract rom.bin --variant 0x12345678 --output extracted
```

Replace the example ID with the variant ID from your image. `--variant` applies only to ROM images, not ROFS/ROFx. The first line of ROM `list` output includes the image offset, runtime base, virtual image size, selected root address, and variant ID.

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

When OOB stripping is enabled, `--offset` refers to the resulting data stream after OOB removal.

### 5. Damaged BytePair Pages

By default, extraction stops when an invalid pageable ROM payload page is encountered, including a corrupt BytePair-compressed page. To continue recovery, enable zero substitution:

```bash
python3 RofsExtractor.py extract rom.bin \
  --ignore-corrupt-pages \
  --output recovered
```

This option applies only to ROM images. It is enabled after directory parsing, so it cannot bypass errors encountered while opening, scanning, or listing the directory tree. It also does not recover truncated unpaged data. The tool warns when substituting a page and reports the number of distinct corrupt pages after extraction. Files using those pages may be incomplete or unusable.

## Output Names and Validation

Names containing Windows-special characters, control characters, percent signs, or trailing dots/spaces are escaped as `%XXXX`; reserved device names receive a `%RESERVED%` prefix. This naming policy is used on every host platform. The `list` command and `--pattern` filter use the original image names.

Invalid UTF-16 names, unsafe path components, output paths escaping the destination, case-insensitive output name collisions, and attempts to overwrite the input image are rejected. Extraction creates parent directories as needed and may overwrite existing output files. An error stops extraction; files already written remain in the destination.
