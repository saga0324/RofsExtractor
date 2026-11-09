#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from functools import lru_cache
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

    def read_file(self, entry: RofsEntry) -> bytes:
        start = self._to_file_offset(entry.address)
        end = start + entry.size
        if start < self.header.base_offset or end > len(self.data):
            raise RofsError(f'file outside input: {entry.image_path}')
        return self.data[start:end]

    def list_entries(self) -> list[RofsEntry]:
        entries: list[RofsEntry] = []
        self._walk_dir(self._to_file_offset(self.header.dir_tree_offset), "", entries)
        return entries

    def extract(self, output_dir: Path, entries: Iterable[RofsEntry]) -> int:
        return extract_entries(self, output_dir, entries)

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
        if not hasattr(self, '_ancestors'):
            self._ancestors = set()
        if dir_offset in self._ancestors or len(self._ancestors) >= 128:
            raise RofsError('cyclic or excessively deep ROFS directory tree')
        self._ancestors.add(dir_offset)
        try:
            self._walk_dir_contents(dir_offset, path, entries)
        finally:
            self._ancestors.remove(dir_offset)

    def _walk_dir_contents(self, dir_offset: int, path: str, entries: list[RofsEntry]) -> None:
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
        name = self.data[name_start:name_end].decode("utf-16le")
        validate_name(name)
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


def validate_name(name: str) -> None:
    if not name or name in ('.', '..') or any(c in name for c in '/\\\0'):
        raise RofsError(f'invalid directory entry name: {name!r}')


def host_name(name: str) -> str:
    validate_name(name)
    result = ''.join(f'%{ord(c):04X}' if c in '<>:"|?*%' or ord(c) < 32
                     or (i >= len(name.rstrip('. '))) else c for i, c in enumerate(name))
    if re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', result, re.I):
        result = '%RESERVED%' + result
    return result


def extract_entries(image, output_dir: Path, entries: Iterable[RofsEntry]) -> int:
    root = output_dir.resolve()
    seen = set()
    count = 0
    for entry in entries:
        relative = Path(*(host_name(n) for n in entry.image_path.split('/')))
        target = root / relative
        if not target.resolve().is_relative_to(root):
            raise RofsError(f'output path escapes destination: {entry.image_path}')
        key = relative.as_posix().casefold()
        if key in seen:
            raise RofsError(f'output name collision: {entry.image_path}')
        seen.add(key)
        if entry.is_dir:
            target.mkdir(parents=True, exist_ok=True)
            continue
        if target.resolve() == image.filename.resolve():
            raise RofsError('output would overwrite the input image')
        data = image.read_file(entry)  # Decode before creating a partial file.
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        count += 1
    return count


def bytepair_decompress(source: bytes, output_size: int = 4096) -> bytes:
    if not source:
        raise RofsError('empty BytePair page')
    pos = 0
    def take():
        nonlocal pos
        if pos >= len(source):
            raise RofsError('truncated BytePair page')
        value = source[pos]
        pos += 1
        return value
    count = take()
    marker = -1
    left = list(range(256))
    right = [0] * 256
    if count:
        marker = take()
        left[marker] = marker ^ 255
        if count < 32:
            tokens = [tuple(take() for _ in range(3)) for _ in range(count)]
        else:
            masks = bytes(take() for _ in range(32))
            tokens = [(n, take(), take()) for n in range(256) if masks[n >> 3] & (1 << (n & 7))]
            if len(tokens) != count:
                raise RofsError('BytePair token count mismatch')
        used = set()
        for token, a, b in tokens:
            if token == marker or token in used or token == a:
                raise RofsError('invalid BytePair token table')
            used.add(token)
            left[token], right[token] = a, b
    result = bytearray()
    steps = 0
    while pos < len(source):
        token = take()
        if token == marker:
            result.append(take())
        else:
            stack = [token]
            while stack:
                steps += 1
                if steps > output_size * 512 or len(stack) > 256:
                    raise RofsError('cyclic BytePair token table')
                token = stack.pop()
                if left[token] == token:
                    result.append(token)
                else:
                    stack.extend((right[token], left[token]))
                if len(result) > output_size:
                    raise RofsError('BytePair page exceeds expected size')
        if len(result) > output_size:
            raise RofsError('BytePair page exceeds expected size')
    if len(result) != output_size:
        raise RofsError(f'BytePair page size {len(result)}; expected {output_size}')
    return bytes(result)


@dataclass(frozen=True)
class RomHeader:
    base_offset: int
    rom_base: int
    image_size: int
    root_list: int
    pageable_start: int
    page_index: int
    roots: tuple[tuple[int, int], ...]
    sorted_directories: bool
    image_type: str = 'ROM'


class SymbianRomImage:
    def __init__(self, filename: Path, data: bytes, offset: int = 0, variant: int | None = None):
        self.filename, self.data = filename, data
        self.ignore_corrupt_pages = False
        self.corrupt_pages = set()
        self._page = lru_cache(maxsize=2048)(self._read_page)
        self.header = self._read_header(offset)
        if variant is None:
            if len(self.header.roots) != 1:
                raise RofsError('ROM has multiple root variants; select one with --variant')
            self.variant = self.header.roots[0][0]
            self.root_address = self.header.roots[0][1]
        else:
            roots = [address for hw, address in self.header.roots if hw == variant]
            if len(roots) != 1:
                raise RofsError(f'ROM root variant 0x{variant:x} not found or ambiguous')
            self.variant, self.root_address = variant, roots[0]

    def _read_header(self, offset: int) -> RomHeader:
        if offset < 0 or offset + 0x200 > len(self.data):
            raise RofsError('ROM header outside input')
        jump = struct.unpack_from('<I', self.data, offset)[0]
        if jump >> 24 != 0xea and jump & 0xfffff000 != 0xe59ff000:
            raise RofsError(f'no ARM ROM header at 0x{offset:x}')
        base, size, root = struct.unpack_from('<3I', self.data, offset + 0x8c)
        if (base < 0x10000000 or base & 4095 or size < 0x200 or size > 0x80000000
                or base + size > 0x100000000 or not base <= root < base + size - 4):
            raise RofsError('implausible ROM address/size/root fields')
        if struct.unpack_from('<I', self.data, offset + 0xec)[0] != 0:
            raise RofsError('whole-image ROM compression is not supported')
        pageable, _, index = struct.unpack_from('<3I', self.data, offset + 0x148)
        if pageable:
            pages = (size + 4095) // 4096
            if (pageable & 4095 or pageable >= size or index < 0x200
                    or index + pages * 8 > pageable or offset + pageable > len(self.data)):
                raise RofsError('invalid ROM demand-paging layout')
        else:
            index = 0
            if offset + size > len(self.data):
                raise RofsError('unpaged ROM is truncated')
        root_offset = root - base
        if root_offset + 4 > (pageable or size):
            raise RofsError('ROM root list is not in unpaged data')
        count = struct.unpack_from('<I', self.data, offset + root_offset)[0]
        if not 1 <= count <= 32 or root_offset + 4 + count * 8 > (pageable or size):
            raise RofsError('invalid ROM root variant list')
        roots = tuple(struct.unpack_from('<II', self.data, offset + root_offset + 4 + i * 8) for i in range(count))
        if len({hw for hw, _ in roots}) != count or any(not base <= a < base + size - 4 for _, a in roots):
            raise RofsError('invalid ROM root addresses')
        sorted_directories = True
        primary = struct.unpack_from('<I', self.data, offset + 0xa0)[0] - base
        if 0 <= primary <= (pageable or size) - 10:
            module_addr = struct.unpack_from('<I', self.data, offset + primary + 4)[0]
            module = module_addr - base
            if 0 <= module <= (pageable or size) - 0x64:
                uid = struct.unpack_from('<I', self.data, offset + module)[0]
                code = struct.unpack_from('<I', self.data, offset + module + 0x14)[0]
                if uid in (0x10000079, 0x1000007a) and code - module_addr == 0x64:
                    sorted_directories = False
        return RomHeader(offset, base, size, root, pageable, index, roots, sorted_directories)

    def _read_page(self, number: int) -> bytes:
        h = self.header
        virtual = number * 4096
        if not h.pageable_start or virtual < h.pageable_start:
            data = self.data[h.base_offset + virtual:h.base_offset + min(virtual + 4096, h.image_size)]
            if len(data) != min(4096, h.image_size - virtual):
                raise RofsError('truncated unpaged ROM data')
            return data
        try:
            table = h.base_offset + h.page_index + number * 8
            start, size, compression, attributes = struct.unpack_from('<IHBB', self.data, table)
            if (not attributes & 1 or not 0 < size <= 4096
                    or start < h.pageable_start or h.base_offset + start + size > len(self.data)):
                raise RofsError('invalid ROM page index entry')
            stored = self.data[h.base_offset + start:h.base_offset + start + size]
            if compression == 0:
                if size != 4096:
                    raise RofsError('invalid uncompressed ROM page size')
                return stored
            if compression == 1:
                return bytepair_decompress(stored)
            raise RofsError(f'unsupported ROM page compression {compression}')
        except (RofsError, struct.error) as error:
            if not self.ignore_corrupt_pages:
                raise RofsError(f'ROM page 0x{number:x}: {error}') from error
            self.corrupt_pages.add(number)
            print(f'warning: ROM page 0x{number:x} replaced with zeroes: {error}', file=sys.stderr)
            return bytes(4096)

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.header.rom_base
        if not 0 <= offset <= offset + size <= self.header.image_size:
            raise RofsError(f'virtual ROM range outside image: 0x{address:x}+0x{size:x}')
        result = bytearray()
        while size:
            number, within = divmod(offset, 4096)
            part = self._page(number)[within:within + size]
            if not part:
                raise RofsError('empty ROM page read')
            result.extend(part)
            offset += len(part)
            size -= len(part)
        return bytes(result)

    def list_entries(self) -> list[RofsEntry]:
        entries = []
        def walk(address, path, ancestors):
            if address in ancestors or len(ancestors) >= 128:
                raise RofsError('cyclic or excessively deep ROM directory tree')
            length = struct.unpack('<I', self.read(address, 4))[0]
            if length > min(self.header.image_size, 0x1000000):
                raise RofsError('implausible ROM directory size')
            data = self.read(address + 4, length)
            position = 0
            local = []
            offsets = set()
            names = set()
            while position < length:
                if position + 10 > length:
                    raise RofsError('truncated ROM directory entry')
                size, target, attr, nlen = struct.unpack_from('<IIBB', data, position)
                end = position + 10 + nlen * 2
                if not nlen or end > length:
                    raise RofsError('invalid ROM directory name length')
                name = data[position + 10:end].decode('utf-16le')
                validate_name(name)
                if name.casefold() in names:
                    raise RofsError('duplicate ROM directory name')
                names.add(name.casefold())
                if not (self.header.rom_base <= target <= self.header.rom_base + self.header.image_size
                        and 0 <= size <= self.header.image_size):
                    raise RofsError('invalid ROM entry address or length')
                isdir = bool(attr & DIR_ATTR)
                if target + (4 if isdir else size) > self.header.rom_base + self.header.image_size:
                    raise RofsError('ROM entry extends beyond virtual image')
                local.append(RofsEntry(path, name, size, target, attr, 0, b'', isdir, address + 4 + position))
                offsets.add(position // 4)
                position = align4(end)
            if position != length:
                raise RofsError('ROM entry alignment exceeds directory')
            if self.header.sorted_directories:
                dirs, files = struct.unpack('<HH', self.read(address + 4 + length, 4))
                if dirs != sum(e.is_dir for e in local) or files != sum(not e.is_dir for e in local):
                    raise RofsError('ROM directory sort counts do not match entries')
                index = self.read(address + 8 + length, 2 * len(local))
                scaled = struct.unpack('<' + 'H' * len(local), index)
                if len(set(scaled)) != len(scaled) or set(scaled) != offsets:
                    raise RofsError('ROM directory sort offsets do not match entries')
            for entry in local:
                entries.append(entry)
                if len(entries) > 1000000:
                    raise RofsError('directory entry limit exceeded')
                if entry.is_dir:
                    walk(entry.address, entry.image_path, ancestors | {address})
        walk(self.root_address, '', set())
        return entries

    def read_file(self, entry: RofsEntry) -> bytes:
        size = entry.size
        if entry.attr & 0x80 and size >= 0x64:
            header = self.read(entry.address, min(0x78, size))
            if struct.unpack_from('<I', header)[0] in (0x10000079, 0x1000007a):
                code, code_size, data_size = (struct.unpack_from('<I', header, n)[0] for n in (0x14, 0x1c, 0x24))
                header_size = code - entry.address
                if header_size not in (0x64, 0x78) or code_size + data_size > size:
                    raise RofsError(f'invalid ROM executable header: {entry.image_path}')
                size += header_size
        return self.read(entry.address, size)

    def extract(self, output_dir: Path, entries: Iterable[RofsEntry]) -> int:
        return extract_entries(self, output_dir, entries)


def rom_candidates(data: bytes) -> Iterable[int]:
    pattern = rb'\x00[\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0][\x00-\xff][\x10-\xef]'
    for match in re.finditer(pattern, data):
        offset = match.start() - 0x8c
        if offset < 0 or offset + 0x200 > len(data):
            continue
        base, size, root = struct.unpack_from('<3I', data, match.start())
        if 0x200 <= size <= 0x80000000 and base + size <= 0x100000000 and base <= root < base + size - 4:
            yield offset


def open_image(args):
    data = load_image_bytes(args.image, args.nand_page_size, args.nand_oob_size)
    variant = getattr(args, 'variant', None)
    def at(offset):
        if data[offset:offset + 4] in (b'ROFS', b'ROFx'):
            if variant is not None:
                raise RofsError('--variant applies only to ROM images')
            rofs = SymbianRofsImage.__new__(SymbianRofsImage)
            rofs.filename, rofs.data = args.image, data
            rofs.header = rofs._read_header(offset)
            return rofs
        return SymbianRomImage(args.image, data, offset, variant)
    if not args.scan:
        return at(args.offset)
    candidates = set(rom_candidates(data))
    for magic in (b'ROFS', b'ROFx'):
        pos = data.find(magic)
        while pos >= 0:
            candidates.add(pos)
            pos = data.find(magic, pos + 1)
    best = None
    ambiguous_variants = False
    for offset in sorted(candidates):
        try:
            image = at(offset)
            entries = image.list_entries()
            count = sum(not e.is_dir for e in entries)
            if not count:
                continue
            # Sample file contents, not just convincing-looking header fields.
            for entry in [e for e in entries if not e.is_dir][:3]:
                if isinstance(image, SymbianRomImage):
                    image.read(entry.address, min(entry.size, 16))
                else:
                    image.read_file(entry)
            score = count * 4 + len(entries) + (1000 if any(e.image_path.lower().startswith('sys/') for e in entries) else 0)
            if best is None or score > best[0]:
                best = score, image
        except (RofsError, UnicodeError, struct.error, RecursionError) as error:
            ambiguous_variants |= 'multiple root variants' in str(error)
    if best is None:
        if ambiguous_variants:
            raise RofsError('ROM has multiple root variants; select one with --variant')
        raise RofsError('scan found no plausible ROM/ROFS/ROFx image')
    return best[1]


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
    image = open_image(args)
    if isinstance(image, SymbianRomImage):
        print(f'ROM offset=0x{image.header.base_offset:x} base=0x{image.header.rom_base:x} '
              f'size=0x{image.header.image_size:x} root=0x{image.root_address:x} variant=0x{image.variant:x}')
    else:
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
    image = open_image(args)
    entries = image.list_entries()
    if args.ignore_corrupt_pages:
        if not isinstance(image, SymbianRomImage):
            raise RofsError('--ignore-corrupt-pages applies only to ROM pages')
        image.ignore_corrupt_pages = True
    if args.pattern:
        needle = args.pattern.lower()
        entries = [entry for entry in entries if needle in entry.image_path.lower()]
    count = image.extract(args.output, entries)
    print(f"extracted {count} files to {args.output} from offset 0x{image.header.base_offset:x}")
    if isinstance(image, SymbianRomImage) and image.corrupt_pages:
        print(f'warning: {len(image.corrupt_pages)} corrupt pages replaced; output is incomplete', file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RofsExtractor")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="list ROM/ROFS directory entries")
    list_parser.add_argument("image", type=Path)
    list_parser.add_argument("--offset", type=parse_int, default=0, help="ROM/ROFS header offset")
    list_parser.add_argument("--scan", action="store_true", help="heuristically find an embedded ROM/ROFS/ROFx image")
    list_parser.add_argument('--variant', type=parse_int, help='ROM hardware variant ID')
    list_parser.add_argument("--nand-page-size", type=parse_int, default=0, help="strip raw NAND OOB: data page size")
    list_parser.add_argument("--nand-oob-size", type=parse_int, default=0, help="strip raw NAND OOB: spare/OOB size")
    list_parser.set_defaults(func=command_list)

    extract_parser = sub.add_parser("extract", help="extract ROM/ROFS files")
    extract_parser.add_argument("image", type=Path)
    extract_parser.add_argument("-o", "--output", type=Path, default=Path("rofs_extracted"))
    extract_parser.add_argument("--pattern", help="case-insensitive substring filter")
    extract_parser.add_argument("--offset", type=parse_int, default=0, help="ROM/ROFS header offset")
    extract_parser.add_argument("--scan", action="store_true", help="heuristically find an embedded ROM/ROFS/ROFx image")
    extract_parser.add_argument('--variant', type=parse_int, help='ROM hardware variant ID')
    extract_parser.add_argument('--ignore-corrupt-pages', action='store_true', help='replace corrupt ROM payload pages with zeroes and warn')
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
    except (OSError, RofsError, struct.error, UnicodeError) as exc:
        parser.exit(1, f"error: {exc}{os.linesep}")


if __name__ == "__main__":
    raise SystemExit(main())
