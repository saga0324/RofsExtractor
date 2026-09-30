#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DIR_ATTR = 0x10
MIN_ROFS_DIR_HEADER_SIZE = 14
ROFS_UIDS_OFFSET = 2
ROFS_UIDS_SIZE = 16
ROFS_NAME_OFFSET_FIELD = 18
ROFS_ATTR_FIELD = 19
ROFS_ATTR_EXTRA_FIELD = 20
ROFS_NAME_LENGTH_FIELD = 21
ROFS_FILE_ADDRESS_FIELD = 22
ROFS_FILE_SIZE_FIELD = 26
ROFS_NAME_OFFSET = 30
MIN_ROFS_ENTRY_FIXED_SIZE = ROFS_NAME_OFFSET + 2


class RofsError(Exception):
    pass


@dataclass(frozen=True)
class RofsHeader:
    image_type: str
    base_offset: int
    header_size: int
    dir_tree_offset: int
    dir_tree_size: int
    file_entries_offset: int
    file_entries_size: int
    format_version: int
    image_size: int
    max_image_size: int
    adjustment: int


@dataclass(frozen=True)
class RofsEntry:
    path: str
    name: str
    size: int
    address: int
    attr: int
    attr_extra: int
    uids: bytes
    is_dir: bool
    entry_offset: int

    @property
    def image_path(self) -> str:
        if self.path:
            return f"{self.path}/{self.name}"
        return self.name


class SymbianRofsImage:
    def __init__(
        self,
        filename: Path,
        offset: int = 0,
        scan: bool = False,
        nand_page_size: int = 0,
        nand_oob_size: int = 0,
    ) -> None:
        self.filename = filename
        self.data = load_image_bytes(filename, nand_page_size, nand_oob_size)
        self.header = self._scan_header() if scan else self._read_header(offset)

    def list_entries(self) -> list[RofsEntry]:
        entries: list[RofsEntry] = []
        self._walk_dir(self._to_file_offset(self.header.dir_tree_offset), "", entries)
        return entries

    def extract(self, output_dir: Path, entries: Iterable[RofsEntry]) -> int:
        count = 0
        for entry in entries:
            if entry.is_dir:
                continue
            start = self._to_file_offset(entry.address)
            end = start + entry.size
            if start < self.header.base_offset or end > len(self.data):
                print(
                    f"skip out-of-range: {entry.image_path} "
                    f"offset=0x{start:x} size=0x{entry.size:x}"
                )
                continue
            out_path = output_dir / Path(*entry.image_path.split("/"))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(self.data[start:end])
            count += 1
        return count

    def _read_header(self, offset: int) -> RofsHeader:
        if offset < 0 or offset + 40 > len(self.data):
            raise RofsError("ROFS offset is outside the input file")

        ident = self.data[offset : offset + 4]
        if ident == b"ROFS":
            image_type = "ROFS"
        elif ident == b"ROFx":
            image_type = "ROFx"
        else:
            raise RofsError(f"no ROFS/ROFx header at 0x{offset:x}")

        # Header layout from rofsbuild:
        # id, headerSize, dirTreeOffset, dirTreeSize, dirFileEntriesOffset,
        # dirFileEntriesSize, formatVersion, TTime, imageSize, ...
        (
            header_size,
            dir_tree_offset,
            dir_tree_size,
            file_entries_offset,
            file_entries_size,
            format_version,
        ) = struct.unpack_from("<6I", self.data, offset + 4)
        image_size = struct.unpack_from("<I", self.data, offset + 36)[0]

        max_image_size = 0
        for candidate in (44, 48):
            if offset + candidate + 4 <= len(self.data):
                value = struct.unpack_from("<I", self.data, offset + candidate)[0]
                if value >= image_size:
                    max_image_size = value
                    break

        if header_size < 0x20 or header_size > 0x1000:
            raise RofsError(f"implausible header size: 0x{header_size:x}")
        if dir_tree_size == 0:
            raise RofsError("directory tree size is zero")

        # ROFx directory offsets are relative to the core image size. The C++
        # reader subtracts this adjustment when seeking directory blocks.
        adjustment = 0
        if image_type == "ROFx":
            adjustment = dir_tree_offset - header_size

        header = RofsHeader(
            image_type=image_type,
            base_offset=offset,
            header_size=header_size,
            dir_tree_offset=dir_tree_offset,
            dir_tree_size=dir_tree_size,
            file_entries_offset=file_entries_offset,
            file_entries_size=file_entries_size,
            format_version=format_version,
            image_size=image_size,
            max_image_size=max_image_size,
            adjustment=adjustment,
        )

        dir_file_offset = self._to_file_offset_with(header, dir_tree_offset)
        if dir_file_offset < offset or dir_file_offset >= len(self.data):
            raise RofsError(
                f"directory tree points outside the input: 0x{dir_tree_offset:x}"
            )
        return header

    def _scan_header(self) -> RofsHeader:
        best: tuple[int, RofsHeader] | None = None
        for offset in self._candidate_offsets():
            try:
                header = self._read_header(offset)
                score = self._score_header(header)
            except (RofsError, struct.error, RecursionError):
                continue
            if best is None or score > best[0]:
                best = (score, header)
        if best is None:
            raise RofsError("scan found no plausible ROFS/ROFx image")
        return best[1]

    def _candidate_offsets(self) -> Iterable[int]:
        seen: set[int] = set()
        for magic in (b"ROFS", b"ROFx"):
            pos = self.data.find(magic)
            while pos != -1:
                if pos not in seen:
                    seen.add(pos)
                    yield pos
                pos = self.data.find(magic, pos + 1)

    def _score_header(self, header: RofsHeader) -> int:
        old = self.header if hasattr(self, "header") else None
        self.header = header
        try:
            entries = self.list_entries()
            file_count = sum(not entry.is_dir for entry in entries)
            dir_count = sum(entry.is_dir for entry in entries)
            sys_bonus = 1000 if any(entry.image_path.lower().startswith("sys/") for entry in entries) else 0
            return file_count * 4 + dir_count + sys_bonus
        finally:
            if old is not None:
                self.header = old

    def _walk_dir(self, dir_offset: int, path: str, entries: list[RofsEntry]) -> None:
        first_entry, file_block_address, file_block_size, struct_size = self._read_dir(dir_offset)

        if file_block_address and file_block_size:
            self._read_file_entries(
                self._to_file_offset(file_block_address),
                file_block_size,
                path,
                entries,
            )

        subdir_pos = dir_offset + first_entry
        subdir_end = dir_offset + struct_size
        while subdir_pos < subdir_end:
            entry = self._read_entry(subdir_pos, path, is_dir=True)
            entries.append(entry)
            child_path = f"{path}/{entry.name}" if path else entry.name
            self._walk_dir(self._to_file_offset(entry.address), child_path, entries)
            subdir_pos += align4(entry_struct_size(self.data, subdir_pos))

    def _read_dir(self, offset: int) -> tuple[int, int, int, int]:
        if offset < self.header.base_offset or offset + MIN_ROFS_DIR_HEADER_SIZE > len(self.data):
            raise RofsError(f"directory offset out of range: 0x{offset:x}")

        first_entry = struct.unpack_from("<H", self.data, offset)[0]
        file_block_address = struct.unpack_from("<I", self.data, offset + 4)[0]
        file_block_size = struct.unpack_from("<I", self.data, offset + 8)[0]
        struct_size = struct.unpack_from("<H", self.data, offset + 12)[0]

        if first_entry < MIN_ROFS_DIR_HEADER_SIZE or struct_size < first_entry:
            raise RofsError(
                f"bad directory header at 0x{offset:x}: "
                f"first=0x{first_entry:x} struct=0x{struct_size:x}"
            )
        if offset + struct_size > len(self.data):
            raise RofsError(f"directory overruns input at 0x{offset:x}")
        return first_entry, file_block_address, file_block_size, struct_size

    def _read_file_entries(
        self, start: int, size: int, path: str, entries: list[RofsEntry]
    ) -> None:
        pos = start
        end = start + size
        if start < self.header.base_offset or end > len(self.data):
            raise RofsError(f"file-entry block out of range: 0x{start:x}+0x{size:x}")
        while pos < end:
            entry = self._read_entry(pos, path, is_dir=False)
            entries.append(entry)
            pos += entry_struct_size(self.data, pos)

    def _read_entry(self, offset: int, path: str, is_dir: bool) -> RofsEntry:
        if offset + MIN_ROFS_ENTRY_FIXED_SIZE > len(self.data):
            raise RofsError(f"entry offset out of range: 0x{offset:x}")

        struct_size = entry_struct_size(self.data, offset)
        name_offset = self.data[offset + ROFS_NAME_OFFSET_FIELD]
        name_length = self.data[offset + ROFS_NAME_LENGTH_FIELD]
        address = struct.unpack_from("<I", self.data, offset + ROFS_FILE_ADDRESS_FIELD)[0]
        size = struct.unpack_from("<I", self.data, offset + ROFS_FILE_SIZE_FIELD)[0]
        attr = self.data[offset + ROFS_ATTR_FIELD]
        attr_extra = self.data[offset + ROFS_ATTR_EXTRA_FIELD]
        uids = self.data[offset + ROFS_UIDS_OFFSET : offset + ROFS_UIDS_OFFSET + ROFS_UIDS_SIZE]

        name_start = offset + name_offset
        name_end = name_start + name_length * 2
        if name_offset != ROFS_NAME_OFFSET or name_end > offset + struct_size:
            raise RofsError(
                f"bad entry name at 0x{offset:x}: "
                f"nameOffset=0x{name_offset:x} nameLength={name_length} "
                f"structSize=0x{struct_size:x}"
            )
        name = self.data[name_start:name_end].decode("utf-16le", errors="replace")
        entry_is_dir = is_dir or bool(attr & DIR_ATTR)
        return RofsEntry(
            path=path,
            name=name,
            size=size,
            address=address,
            attr=attr,
            attr_extra=attr_extra,
            uids=uids,
            is_dir=entry_is_dir,
            entry_offset=offset,
        )

    def _to_file_offset(self, image_offset: int) -> int:
        return self._to_file_offset_with(self.header, image_offset)

    @staticmethod
    def _to_file_offset_with(header: RofsHeader, image_offset: int) -> int:
        adjusted = image_offset - header.adjustment
        if header.image_type == "ROFx" and adjusted >= 0:
            return header.base_offset + adjusted
        return header.base_offset + image_offset


def entry_struct_size(data: bytes, offset: int) -> int:
    size = struct.unpack_from("<H", data, offset)[0]
    if size < MIN_ROFS_ENTRY_FIXED_SIZE:
        raise RofsError(f"bad entry size at 0x{offset:x}: 0x{size:x}")
    return size


def align4(value: int) -> int:
    return (value + 3) & ~3


def load_image_bytes(path: Path, page_size: int = 0, oob_size: int = 0) -> bytes:
    if not page_size and not oob_size:
        return path.read_bytes()
    if page_size <= 0 or oob_size <= 0:
        raise RofsError("--nand-page-size and --nand-oob-size must be used together")
    out = bytearray()
    step = page_size + oob_size
    with path.open("rb") as f:
        while True:
            chunk = f.read(step * 4096)
            if not chunk:
                break
            pos = 0
            while pos < len(chunk):
                page = chunk[pos : pos + page_size]
                if not page:
                    break
                out.extend(page)
                pos += step
    return bytes(out)


def parse_int(value: str) -> int:
    return int(value, 0)


def command_list(args: argparse.Namespace) -> int:
    image = SymbianRofsImage(args.image, args.offset, args.scan, args.nand_page_size, args.nand_oob_size)
    print(
        f"{image.header.image_type} offset=0x{image.header.base_offset:x} "
        f"dir=0x{image.header.dir_tree_offset:x}+0x{image.header.dir_tree_size:x} "
        f"files=0x{image.header.file_entries_offset:x}+0x{image.header.file_entries_size:x}"
    )
    entries = image.list_entries()
    for entry in entries:
        kind = "d" if entry.is_dir else "f"
        print(f"{kind}  {entry.address:08x}  {entry.size:08x}  {entry.image_path}")
    print(f"\n{sum(not e.is_dir for e in entries)} files, {sum(e.is_dir for e in entries)} directories")
    return 0


def command_extract(args: argparse.Namespace) -> int:
    image = SymbianRofsImage(args.image, args.offset, args.scan, args.nand_page_size, args.nand_oob_size)
    entries = image.list_entries()
    if args.pattern:
        needle = args.pattern.lower()
        entries = [entry for entry in entries if needle in entry.image_path.lower()]
    count = image.extract(args.output, entries)
    print(f"extracted {count} files to {args.output} from offset 0x{image.header.base_offset:x}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RofsExtractor")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="list ROFS directory entries")
    list_parser.add_argument("image", type=Path)
    list_parser.add_argument("--offset", type=parse_int, default=0, help="ROFS header offset")
    list_parser.add_argument("--scan", action="store_true", help="heuristically find an embedded ROFS/ROFx image")
    list_parser.add_argument("--nand-page-size", type=parse_int, default=0, help="strip raw NAND OOB: data page size")
    list_parser.add_argument("--nand-oob-size", type=parse_int, default=0, help="strip raw NAND OOB: spare/OOB size")
    list_parser.set_defaults(func=command_list)

    extract_parser = sub.add_parser("extract", help="extract ROFS files")
    extract_parser.add_argument("image", type=Path)
    extract_parser.add_argument("-o", "--output", type=Path, default=Path("rofs_extracted"))
    extract_parser.add_argument("--pattern", help="case-insensitive substring filter")
    extract_parser.add_argument("--offset", type=parse_int, default=0, help="ROFS header offset")
    extract_parser.add_argument("--scan", action="store_true", help="heuristically find an embedded ROFS/ROFx image")
    extract_parser.add_argument("--nand-page-size", type=parse_int, default=0, help="strip raw NAND OOB: data page size")
    extract_parser.add_argument("--nand-oob-size", type=parse_int, default=0, help="strip raw NAND OOB: spare/OOB size")
    extract_parser.set_defaults(func=command_extract)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except BrokenPipeError:
        return 1
    except (OSError, RofsError, struct.error) as exc:
        parser.exit(1, f"error: {exc}{os.linesep}")


if __name__ == "__main__":
    raise SystemExit(main())
