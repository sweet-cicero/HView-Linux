#!/usr/bin/env python3
"""Check reachable ELF workflows through a Linux pseudoterminal."""

# These imports create independent ELF fixtures, sparse files, and terminal sessions.
# Independent terminal sessions isolate claims from text that an earlier action displayed.
import os
from pathlib import Path
import struct
import sys
import tempfile

from terminal_probe import run_session


# These byte sequences select current editing, history, mode, navigation, and Tools controls.
# The address-space limit proves that sparse fixtures do not enter process memory.
ALT_E = b"\x1be"
ALT_N = b"\x1bn"
ALT_P = b"\x1bp"
ALT_S = b"\x1bs"
CTRL_Q = b"\x11"
CTRL_T = b"\x14"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
DOWN = b"\x1b[B"
ENTER = b"\r"
ESCAPE = b"\x1b"
RIGHT = b"\x1b[C"
ADDRESS_LIMIT = 256 * 1024 * 1024
ELF_BASE = 0x400000
ELF_LOAD = 0x100
ELF_TEXT = 0x110
ELF_SECTION_TABLE = 0x300


# These assertions check exact terminal facts and the order of state changes.
# Failures identify the missing fact before a later check reads fixture bytes.
def require(output: bytes, *values: bytes) -> None:
    """Require each terminal value."""
    for value in values:
        if value not in output:
            raise AssertionError(f"The terminal output lacks: {value!r}")


def require_order(output: bytes, *values: bytes) -> None:
    """Require terminal values in order."""
    position = 0
    for value in values:
        position = output.find(value, position)
        if position < 0:
            raise AssertionError(f"The terminal output lacks an ordered value: {value!r}")
        position += len(value)


# This selector returns the final complete header for one named source.
# Header checks use the last frame, which excludes stale text from previous modal views.
def last_header(output: bytes, name: str) -> bytes:
    """Return the final complete header for one file."""
    position = output.rfind(name.encode())
    if position < 0:
        raise AssertionError(f"The terminal output lacks the file name: {name}")
    start = output.rfind(b"\x1b[1;1H", 0, position)
    end = output.find(b"\x1b[2;1H", position)
    if start < 0 or end < 0:
        raise AssertionError("The terminal output lacks a complete header.")
    return output[start:end]


# These fixed-width writers place independent little-endian values into each fixture.
# The fixture builder uses no production parser or project fixture helper.
def put16(data: bytearray, offset: int, value: int) -> None:
    """Write one little-endian 16-bit value."""
    struct.pack_into("<H", data, offset, value)


def put32(data: bytearray, offset: int, value: int) -> None:
    """Write one little-endian 32-bit value."""
    struct.pack_into("<I", data, offset, value)


def put64(data: bytearray, offset: int, value: int) -> None:
    """Write one little-endian 64-bit value."""
    struct.pack_into("<Q", data, offset, value)


# This helper writes one class-specific section record into the shared fixture.
# The caller supplies exact ELF values, and the builder writes only standard fields.
def put_section(
    data: bytearray,
    bits: int,
    index: int,
    name: int,
    section_type: int,
    flags: int,
    address: int,
    offset: int,
    size: int,
    align: int,
) -> None:
    """Write one ELF section record."""
    stride = 40 if bits == 32 else 64
    at = ELF_SECTION_TABLE + index * stride
    put32(data, at, name)
    put32(data, at + 4, section_type)
    if bits == 32:
        put32(data, at + 8, flags)
        put32(data, at + 12, address)
        put32(data, at + 16, offset)
        put32(data, at + 20, size)
        put32(data, at + 32, align)
    else:
        put64(data, at + 8, flags)
        put64(data, at + 16, address)
        put64(data, at + 24, offset)
        put64(data, at + 32, size)
        put64(data, at + 48, align)


# This builder creates one bounded ELF32 or ELF64 file with controlled load and section tables.
# ET_REL omits its program table and keeps Code addresses in the File domain.
def elf_fixture(
    bits: int,
    machine: int,
    file_type: int,
    code: bytes,
    entry: int | None = None,
) -> bytes:
    """Create one independent ELF fixture."""
    if bits not in (32, 64):
        raise ValueError("The ELF fixture width must be 32 or 64.")
    data = bytearray(0x500)
    data[:7] = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1, 1))
    put16(data, 16, file_type)
    put16(data, 18, machine)
    put32(data, 20, 1)
    resolved_entry = 0 if file_type == 1 else ELF_BASE + 0x10
    if entry is not None:
        resolved_entry = entry

    # This header section declares one PT_LOAD record for image files and four section records.
    # The program and section tables remain separate from all file-backed section data.
    program_offset = 0 if file_type == 1 else (52 if bits == 32 else 64)
    program_size = 32 if bits == 32 else 56
    if bits == 32:
        put32(data, 24, resolved_entry)
        put32(data, 28, program_offset)
        put32(data, 32, ELF_SECTION_TABLE)
        put16(data, 40, 52)
        put16(data, 42, program_size)
        put16(data, 44, 0 if file_type == 1 else 1)
        put16(data, 46, 40)
        put16(data, 48, 4)
        put16(data, 50, 3)
    else:
        put64(data, 24, resolved_entry)
        put64(data, 32, program_offset)
        put64(data, 40, ELF_SECTION_TABLE)
        put16(data, 52, 64)
        put16(data, 54, program_size)
        put16(data, 56, 0 if file_type == 1 else 1)
        put16(data, 58, 64)
        put16(data, 60, 4)
        put16(data, 62, 3)

    # This program section maps file bytes 0x100 through 0x1FF to declared virtual addresses.
    # The next 0x80 virtual bytes form a memory-only tail without a file offset.
    if file_type != 1:
        at = program_offset
        if bits == 32:
            put32(data, at, 1)
            put32(data, at + 4, ELF_LOAD)
            put32(data, at + 8, ELF_BASE)
            put32(data, at + 16, 0x100)
            put32(data, at + 20, 0x180)
            put32(data, at + 24, 5)
            put32(data, at + 28, 1)
        else:
            put32(data, at, 1)
            put32(data, at + 4, 5)
            put64(data, at + 8, ELF_LOAD)
            put64(data, at + 16, ELF_BASE)
            put64(data, at + 32, 0x100)
            put64(data, at + 40, 0x180)
            put64(data, at + 48, 1)

    # This section table names one executable section, one NOBITS section, and its string table.
    # The code bytes and one unmapped byte give later Code checks deterministic input.
    names = b"\0.text\0.bss\0.shstrtab\0"
    data[0x280 : 0x280 + len(names)] = names
    text_address = 0 if file_type == 1 else ELF_BASE + 0x10
    bss_address = 0 if file_type == 1 else ELF_BASE + 0x100
    put_section(data, bits, 1, 1, 1, 6, text_address, ELF_TEXT, 0x20, 16)
    put_section(data, bits, 2, 7, 8, 3, bss_address, 0x200, 0x40, 16)
    put_section(data, bits, 3, 12, 3, 0, 0, 0x280, len(names), 1)
    data[ELF_TEXT : ELF_TEXT + len(code)] = code
    data[0x120] = 0xC3
    data[0x210] = 0x90
    return bytes(data)


# This verifier reads fixture facts with independent struct operations.
# The checks fail before the terminal probe can use a malformed local fixture.
def verify_fixture(data: bytes, bits: int, machine: int, file_type: int, entry: int) -> None:
    """Verify one independently built ELF fixture."""
    if data[:7] != b"\x7fELF" + bytes((1 if bits == 32 else 2, 1, 1)):
        raise AssertionError("The ELF identification bytes are incorrect.")
    if struct.unpack_from("<HHI", data, 16) != (file_type, machine, 1):
        raise AssertionError("The ELF type, machine, or version is incorrect.")
    if bits == 32:
        values = struct.unpack_from("<III", data, 24)
        counts = struct.unpack_from("<HHHHHH", data, 40)
    else:
        values = struct.unpack_from("<QQQ", data, 24)
        counts = struct.unpack_from("<HHHHHH", data, 52)
    expected_program = 0 if file_type == 1 else (52 if bits == 32 else 64)
    if values != (entry, expected_program, ELF_SECTION_TABLE):
        raise AssertionError("The ELF entry or table offset is incorrect.")
    expected_counts = (
        52 if bits == 32 else 64,
        32 if bits == 32 else 56,
        0 if file_type == 1 else 1,
        40 if bits == 32 else 64,
        4,
        3,
    )
    if counts != expected_counts:
        raise AssertionError("The ELF table sizes or counts are incorrect.")
    names = b"\0.text\0.bss\0.shstrtab\0"
    if data[0x280 : 0x280 + len(names)] != names:
        raise AssertionError("The ELF section-name table is incorrect.")


# This helper returns the common selected-offset text from a terminal frame.
# Hex and structure navigation checks use the value after their isolated action completes.
def offset_header(offset: int) -> bytes:
    """Return one selected-offset header value."""
    return f"{offset:08X}│HView-Linux".encode()


# This action builder selects or removes one explicit raw model.
# Ctrl+T then R preserves the established Tools binding.
def raw_model(value: str) -> list[bytes]:
    """Return actions that set one raw model."""
    return [CTRL_T, b"r", value.encode(), ENTER]


# This check opens mapped, unmapped, ELF64, and relocatable Code bytes.
# Separate terminal sessions prevent one format label from satisfying another case.
def check_code_labels(binary: Path, root: Path) -> None:
    """Check buffered ELF Code labels and address domains."""
    elf32 = root / "e32.elf"
    elf64 = root / "e64.elf"
    relocatable = root / "rel.elf"
    config32 = root / "code32.ini"
    config64 = root / "code64.ini"
    elf32.write_bytes(elf_fixture(32, 3, 2, b"\x90\xC3"))
    elf64.write_bytes(elf_fixture(64, 62, 3, b"\x90\xC3"))
    relocatable.write_bytes(elf_fixture(32, 3, 1, b"\x90\xC3", 0))
    config32.write_bytes(b"[HView-Linux 1]\nDefaultCodeSize=32\n")
    config64.write_bytes(b"[HView-Linux 1]\nDefaultCodeSize=64\n")

    # The mapped ELF32 frame uses the declared VA and the configured 32-bit x86 width.
    mapped = run_session(
        binary,
        ["--config", str(config32), "--mode=code", "--offset=110", str(elf32)],
        [CTRL_Q],
    )
    require(last_header(mapped, elf32.name), b"ELF", b"a32", b".00400010")
    require(mapped, b"nop")

    # The unmapped ELF32 byte keeps the File domain while the machine still selects x86 decoding.
    unmapped = run_session(
        binary,
        ["--config", str(config32), "--mode=code", "--offset=210", str(elf32)],
        [CTRL_Q],
    )
    require(last_header(unmapped, elf32.name), b"FILE", b"a32", offset_header(0x210))
    require(unmapped, b"nop")

    # The ELF64 dynamic image accepts its class-machine pair and uses the configured 64-bit x86 width.
    wide = run_session(
        binary,
        ["--config", str(config64), "--mode=code", "--offset=110", str(elf64)],
        [CTRL_Q],
    )
    require(last_header(wide, elf64.name), b"ELF", b"a64", b".00400010")
    require(wide, b"nop")

    # The relocatable file uses a file address because ET_REL has no virtual mapping.
    relative = run_session(
        binary,
        ["--config", str(config32), "--mode=code", "--offset=110", str(relocatable)],
        [CTRL_Q],
    )
    require(last_header(relative, relocatable.name), b"FILE", b"a32", offset_header(ELF_TEXT))
    require(relative, b"nop")


# This check enters file and virtual addresses through the current Address tool.
# Each conversion session checks its result and its handler-driven cursor change.
def check_addresses(binary: Path, path: Path) -> None:
    """Check ELF File and VA conversion."""
    expected = b"File=00000110 VA=0000000000400010"
    for address in (b"F 110", b"V 400010"):
        output = run_session(
            binary,
            ["--mode=hex", str(path)],
            [CTRL_T, b"a", address, ENTER, ENTER, CTRL_Q],
        )
        require(output, b"ELF address: F file or V VA (hex)", expected)
        require(last_header(output, path.name), offset_header(ELF_TEXT))

    # An unmapped file byte returns no VA and remains selectable through the result browser.
    unmapped = run_session(
        binary,
        ["--mode=hex", str(path)],
        [CTRL_T, b"a", b"F 210", ENTER, ENTER, CTRL_Q],
    )
    result = b"File=00000210 VA=-"
    require(unmapped, result)
    require(last_header(unmapped, path.name), offset_header(0x210))

    # A memory-only VA reports its exact address and does not invent a file byte.
    tail = run_session(
        binary,
        ["--mode=hex", str(path)],
        [CTRL_T, b"a", b"V 400120", ENTER, ENTER, CTRL_Q],
    )
    require(
        tail,
        b"File=- VA=0000000000400120",
        b"No file bytes exist for this virtual address.",
    )

    # An RVA request reaches the ELF mapping handler and returns its format-specific notice.
    rva = run_session(
        binary,
        ["--mode=hex", str(path)],
        [CTRL_T, b"a", b"R 1010", ENTER, ENTER, CTRL_Q],
    )
    require(rva, b"ELF files have no RVA.")


# This check applies EntryPoint and Virtual startup to the same mapped source byte.
# Separate processes ensure that one startup route cannot satisfy the other route.
def check_buffered_startup(binary: Path, path: Path) -> None:
    """Check buffered ELF entry and virtual startup."""
    for option in (["--entry-point"], ["--virtual", "400010"]):
        output = run_session(binary, ["--mode=hex", *option, str(path)], [CTRL_Q])
        require(output, offset_header(ELF_TEXT), b"90 C3")


# This check lets ELF entry state select ARM, Thumb, and AArch64 decoding.
# Each case uses a fresh source and terminal session with controlled instruction bytes.
def check_arm_families(binary: Path, root: Path) -> None:
    """Check automatic ELF ARM-family selection."""
    cases = [
        ("arm", 32, 40, ELF_BASE + 0x10, bytes.fromhex("00 00 A0 E1"), b"ARM", b"mov"),
        ("thumb", 32, 40, ELF_BASE + 0x11, bytes.fromhex("00 BF"), b"THUMB", b"nop"),
        ("arm64", 64, 183, ELF_BASE + 0x10, bytes.fromhex("1F 20 03 D5"), b"ARM64", b"nop"),
    ]
    for name, bits, machine, entry, code, label, mnemonic in cases:
        path = root / f"{name}.elf"
        path.write_bytes(elf_fixture(bits, machine, 2, code, entry))
        output = run_session(
            binary,
            ["--mode=code", "--entry-point", str(path)],
            [CTRL_Q],
        )
        require(last_header(output, path.name), b"ELF", label, b".00400010")
        require(output, mnemonic)


# This check gives raw selection priority and then restores automatic Thumb metadata.
# A second source proves that explicit raw viewing also works for malformed ELF bytes.
def check_raw_override(binary: Path, root: Path) -> None:
    """Check explicit raw ELF viewing and AUTO restoration."""
    path = root / "auto.elf"
    path.write_bytes(elf_fixture(32, 40, 2, bytes.fromhex("00 BF"), ELF_BASE + 0x11))
    output = run_session(
        binary,
        ["--mode=code", "--offset=110", str(path)],
        [*raw_model("ARM LE 50000000"), *raw_model("AUTO"), CTRL_Q],
    )
    require_order(output, b".00400010", b".50000110", b".00400010")
    final = last_header(output, path.name)
    require(final, b"ELF", b"THUMB")
    if b"RAW" in final:
        raise AssertionError("AUTO did not remove the explicit raw ELF model.")

    # The malformed file starts in Hex mode, so the explicit model owns Code before parsing begins.
    malformed = root / "raw.elf"
    raw = bytearray(0x30)
    raw[:4] = b"\x7fELF"
    raw[0x20:0x22] = b"\x90\xC3"
    malformed.write_bytes(raw)
    explicit = run_session(
        binary,
        ["--mode=hex", "--offset=20", str(malformed)],
        [*raw_model("X86 32 LE 1000"), b"m", b"c", ENTER, CTRL_Q],
    )
    require(last_header(explicit, malformed.name), b"RAW", b"a32", b".00001020")
    require(explicit, b"nop")


# This helper opens the ELF structure browser and selects one visible row.
# The returned frame proves that the accepted row used its declared navigation offset.
def select_structure(binary: Path, path: Path, row: int, offset: int) -> None:
    """Select one ELF structure row."""
    output = run_session(
        binary,
        ["--mode=hex", "--offset=110", str(path)],
        [CTRL_T, b"p", *([DOWN] * row), ENTER, CTRL_Q],
    )
    require(output, b"ELF structures")
    require(last_header(output, path.name), offset_header(offset))


# This check displays bounded header, entry, program, and section rows.
# Separate selection sessions verify header, program, file-backed section, and NOBITS navigation.
def check_structures(binary: Path, path: Path) -> None:
    """Check buffered ELF structure rows and navigation."""
    before = path.read_bytes()
    output = run_session(
        binary,
        ["--mode=hex", "--offset=110", str(path)],
        [CTRL_T, b"p", RIGHT, RIGHT, RIGHT, RIGHT, ESCAPE, CTRL_Q],
    )
    require(
        output,
        b"ELF32 header | Type=2 Machine=0x0003 Entry=0000000000400010",
        b"Entry | File=0000000000000110 VA=0000000000400010",
        b"Program[0] PT_LOAD | File=0000000000000100 VA=0000000000400000",
        b"Section[1] .text SHT_PROGBITS | File=0000000000000110",
        b"Section[2] .bss SHT_NOBITS | File=- VA=0000000000400100",
        b"Section[3] .shstrtab SHT_STRTAB | File=0000000000000280",
    )
    select_structure(binary, path, 0, 0)
    select_structure(binary, path, 2, ELF_LOAD)
    select_structure(binary, path, 3, ELF_TEXT)
    select_structure(binary, path, 4, ELF_SECTION_TABLE + 2 * 40)
    if path.read_bytes() != before:
        raise AssertionError("ELF structure browsing changed the source file.")


# This check creates shared section names that exceed the aggregate limit before the browser row limit.
# The address-space limit requires bounded text allocation and a clear modal error.
def check_structure_text_limit(binary: Path, root: Path) -> None:
    """Check the ELF structure text limit through the terminal."""
    count = 1_024
    names = b"\0" + b"\xff" * 4_096 + b"\0"
    names_file = ELF_SECTION_TABLE + count * 64
    data = bytearray(names_file + len(names))
    data[:64] = elf_fixture(64, 62, 1, b"")[:64]
    put16(data, 60, count)
    put16(data, 62, 1)
    data[names_file:] = names

    # The string-table section owns the shared name bytes.
    # The remaining NOBITS sections use the same name without overlapping file data.
    put_section(data, 64, 1, 1, 3, 0, 0, names_file, len(names), 1)
    for index in range(2, count):
        put_section(data, 64, index, 1, 8, 0, 0, 0, 1, 1)
    path = root / "text-limit.elf"
    path.write_bytes(data)
    # Enter closes the parser error before Ctrl+Q quits the viewer.
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [CTRL_T, b"p", ENTER, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"The ELF structure text exceeds the limit of 16 MiB.")
    require(last_header(output, path.name), offset_header(0))
    if path.read_bytes() != data:
        raise AssertionError("The ELF structure text error changed the source file.")


# This check edits the real entry field and reparses the current buffer for every browser opening.
# Undo and Redo change the row before Alt+S saves the final header byte.
def check_current_header_edit(binary: Path, root: Path) -> None:
    """Check current-buffer ELF header editing and save."""
    path = root / "edit.elf"
    original = elf_fixture(32, 3, 2, b"\x90\xC3")
    path.write_bytes(original)
    changed_row = b"Entry | File=0000000000000120 VA=0000000000400020"
    original_row = b"Entry | File=0000000000000110 VA=0000000000400010"
    output = run_session(
        binary,
        ["--mode=hex", "--offset=18", str(path)],
        [
            ALT_E,
            b"20",
            CTRL_T,
            b"p",
            ESCAPE,
            CTRL_Z,
            CTRL_T,
            b"p",
            ESCAPE,
            CTRL_Y,
            CTRL_T,
            b"p",
            ESCAPE,
            ALT_S,
            CTRL_Q,
        ],
    )
    require_order(output, changed_row, original_row, changed_row)
    saved = path.read_bytes()
    if saved[0x18] != 0x20 or saved[:0x18] != original[:0x18] or saved[0x19:] != original[0x19:]:
        raise AssertionError("The saved ELF header edit changed unexpected bytes.")

    # A fresh startup must use the saved entry field and select its new mapped file byte.
    restarted = run_session(binary, ["--mode=hex", "--entry-point", str(path)], [CTRL_Q])
    require(restarted, offset_header(0x120), b"C3")


# This check submits three malformed ELF files through Ctrl+T then P.
# Each isolated notice proves that the current input handler reports its own parser error.
def check_malformed_notices(binary: Path, root: Path) -> None:
    """Check malformed ELF structure notices."""
    valid = elf_fixture(32, 3, 2, b"\x90")
    cases: list[tuple[str, bytes, bytes]] = []
    cases.append(("short", valid[:20], b"The ELF header is incomplete."))
    big_endian = bytearray(valid)
    big_endian[5] = 2
    cases.append(("big", bytes(big_endian), b"Big-endian ELF files are unsupported."))
    core = bytearray(valid)
    put16(core, 16, 4)
    cases.append(("core", bytes(core), b"The ELF file type is unsupported."))
    for name, data, notice in cases:
        path = root / f"{name}.elf"
        path.write_bytes(data)
        output = run_session(
            binary,
            ["--mode=hex", str(path)],
            [CTRL_T, b"p", ENTER, CTRL_Q],
        )
        require(output, notice)


# This writer creates one sparse ELF64 image with a single high or low PT_LOAD target.
# Only the fixed header and marker allocate disk blocks.
def sparse_elf64(
    path: Path,
    length: int,
    load_offset: int,
    load_address: int,
    marker: bytes,
) -> int:
    """Create one sparse ELF64 image and return its entry file offset."""
    entry_file = load_offset + 0x10
    prefix = bytearray(64 + 56)
    prefix[:7] = b"\x7fELF\x02\x01\x01"
    put16(prefix, 16, 2)
    put16(prefix, 18, 62)
    put32(prefix, 20, 1)
    put64(prefix, 24, load_address + 0x10)
    put64(prefix, 32, 64)
    put16(prefix, 52, 64)
    put16(prefix, 54, 56)
    put16(prefix, 56, 1)
    put32(prefix, 64, 1)
    put32(prefix, 68, 5)
    put64(prefix, 72, load_offset)
    put64(prefix, 80, load_address)
    put64(prefix, 96, 0x40)
    put64(prefix, 104, 0x80)
    put64(prefix, 112, 1)

    # This file section writes the bounded prefix and one entry marker before it flushes the source.
    # The logical length can exceed four GiB without dense storage.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.ftruncate(descriptor, length)
        os.pwrite(descriptor, prefix, 0)
        os.pwrite(descriptor, marker, entry_file)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return entry_file


# This check starts directly at a file byte above four GiB through two ELF routes.
# A representable inactive target then checks SAV initialization and buffered or paged switching.
def check_sparse_startup_and_switching(binary: Path, root: Path) -> None:
    """Check sparse paged ELF startup and switching."""
    high_path = root / "high.elf"
    high_load = (1 << 32) + 0x100
    high_address = 0x500000000
    high_entry = sparse_elf64(
        high_path,
        high_load + 0x100,
        high_load,
        high_address,
        b"\xC3HI",
    )
    for option in (["--entry-point"], ["--virtual", f"{high_address + 0x10:X}"]):
        output = run_session(
            binary,
            ["--mode=hex", *option, str(high_path)],
            [CTRL_Q],
            address_limit_bytes=ADDRESS_LIMIT,
        )
        require(output, offset_header(high_entry), b"C3 48 49")

    # The inactive paged source uses a legacy-representable cursor while its total length selects paged storage.
    low_path = root / "low.elf"
    low_entry = sparse_elf64(
        low_path,
        64 * 1024 * 1024 + 1,
        0x2000,
        0x600000,
        b"\xC3LO",
    )
    small = root / "small.bin"
    session = root / "switch.sav"
    small.write_bytes(b"small")
    output = run_session(
        binary,
        ["--mode=hex", "--entry-point", "--session", str(session), str(small), str(low_path)],
        [ALT_N, ALT_P, ALT_N, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, small.name.encode(), b"C3 4C 4F")
    require(last_header(output, low_path.name), offset_header(low_entry))


# This entry point builds all fixtures before it starts the isolated terminal checks.
# A successful result means each child process also restored its terminal state.
def main() -> None:
    """Run the ELF terminal checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: elf_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    # These direct assertions validate both class layouts without using application code.
    # The temporary directory then contains all buffered, edited, malformed, and sparse sources.
    verify_fixture(elf_fixture(32, 3, 2, b"\x90"), 32, 3, 2, ELF_BASE + 0x10)
    verify_fixture(elf_fixture(64, 62, 3, b"\x90"), 64, 62, 3, ELF_BASE + 0x10)
    with tempfile.TemporaryDirectory(prefix="hview-elf-") as temporary:
        root = Path(temporary)
        base = root / "base.elf"
        base.write_bytes(elf_fixture(32, 3, 2, b"\x90\xC3"))
        check_code_labels(binary, root)
        check_addresses(binary, base)
        check_buffered_startup(binary, base)
        check_arm_families(binary, root)
        check_raw_override(binary, root)
        check_structures(binary, base)
        check_structure_text_limit(binary, root)
        check_current_header_edit(binary, root)
        check_malformed_notices(binary, root)
        check_sparse_startup_and_switching(binary, root)
    print("ELF terminal probe passed.")


if __name__ == "__main__":
    main()
